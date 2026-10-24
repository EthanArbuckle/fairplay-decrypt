"""FairPlay IPA decryption and page-key derivation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ARM64 = 0x0100000C
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
PAGE_SIZE = 4096
WORK_MASK = bytes.fromhex("c7626110cecd15963d850f6605f11c4b")
CONSTANT = bytes.fromhex("b4f27cb84eaaff3c1309be4089f02972")
CONTEXT_BASE = 0x3E4A45B664EBA141
ROUND_SELECTORS = tuple(
    bytes.fromhex(value)
    for value in (
        "363738393a3b3c3d",
        "383736393a3d3c3b",
        "38363a373c393d3b",
        "37383a363d393b3c",
    )
)
ROUND_CONSTANTS = (0x6EE6B74F, 0x78B72ABF, 0xD227C8EA, 0x0C0081BC)
FINAL_SELECTORS = ((0, 1, 2, 3), (0, 2, 4, 6), (0, 3, 5, 7), (4, 5, 6, 7))
FINAL_WORDS = (0x85FE4668, 0x15EA8FCD, 0x3A17569B, 0x216E68E0)
_FINAL_CONSTANTS = (
    0x4F3DAC1FD3361949,
    0x4F3DAC1F631A63A2,
    0x4F3DAC1F87CD2974,
    0x4F3DAC1F7EA63AB1,
)


@dataclass(frozen=True)
class MachoInfo:
    base: int
    cryptoff: int
    cryptsize: int
    cryptid_offset: int


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def arm64_encryption_info(data: bytes) -> MachoInfo:
    if data[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", data, 4)[0]
        if not 0 < count <= 16 or 8 + count * 20 > len(data):
            raise ValueError("invalid FAT32 architecture table")
        entries = [struct.unpack_from(">IIIII", data, 8 + i * 20) for i in range(count)]
        arm = [(off, size) for cpu, _sub, off, size, _align in entries if cpu == ARM64]
    elif data[:4] == b"\xca\xfe\xba\xbf":
        count = struct.unpack_from(">I", data, 4)[0]
        if not 0 < count <= 16 or 8 + count * 32 > len(data):
            raise ValueError("invalid FAT64 architecture table")
        entries = [
            struct.unpack_from(">IIQQII", data, 8 + i * 32) for i in range(count)
        ]
        arm = [
            (off, size)
            for cpu, _sub, off, size, _align, _reserved in entries
            if cpu == ARM64
        ]
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        arm = [(0, len(data))]
    else:
        raise ValueError("not a supported arm64 Mach-O")
    if len(arm) != 1:
        raise ValueError(f"expected one arm64 slice, found {len(arm)}")
    base, slice_size = arm[0]
    if base + slice_size > len(data) or base + 32 > len(data):
        raise ValueError("arm64 slice exceeds file")
    magic, cpu, _sub, _type, ncmds, sizeofcmds, _flags, _res = struct.unpack_from(
        "<IiiIIIII", data, base
    )
    if magic != 0xFEEDFACF or cpu != ARM64 or ncmds > 1000:
        raise ValueError("invalid arm64 Mach-O header")
    pos = base + 32
    commands_end = pos + sizeofcmds
    if commands_end > base + slice_size:
        raise ValueError("load commands exceed arm64 slice")
    found = []
    for _ in range(ncmds):
        if pos + 8 > commands_end:
            raise ValueError("truncated load command")
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > commands_end:
            raise ValueError("invalid load command")
        if cmd == 0x2C:
            if size < 24:
                raise ValueError("short encryption info command")
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, pos + 8)
            found.append((cryptoff, cryptsize, cryptid, pos + 16))
        pos += size
    if len(found) != 1:
        raise ValueError(f"expected one encryption command, found {len(found)}")
    cryptoff, cryptsize, cryptid, cryptid_offset = found[0]
    if cryptid != 1 or cryptsize == 0 or cryptsize % PAGE_SIZE:
        raise ValueError(f"unsupported cryptid/size: {cryptid}, {cryptsize}")
    if cryptoff + cryptsize > slice_size or cryptid_offset >= base + cryptoff:
        raise ValueError("invalid encrypted region bounds")
    return MachoInfo(base, cryptoff, cryptsize, cryptid_offset)


def _children(data: bytes, start: int, end: int):
    offset = start
    while offset < end:
        if offset + 8 > end:
            raise ValueError("truncated SINF atom")
        size = int.from_bytes(data[offset : offset + 4], "big")
        if size < 8 or offset + size > end:
            raise ValueError(f"invalid SINF atom size at {offset:#x}")
        yield data[offset + 4 : offset + 8], offset + 8, offset + size
        offset += size


def _sinf_field(sinf: bytes, wanted: bytes) -> bytes:
    roots = list(_children(sinf, 0, len(sinf)))
    if len(roots) != 1 or roots[0][0] != b"sinf":
        raise ValueError("expected outer sinf atom")
    schi = [x for x in _children(sinf, roots[0][1], roots[0][2]) if x[0] == b"schi"]
    if len(schi) != 1:
        raise ValueError("expected one schi container")
    fields = [x for x in _children(sinf, schi[0][1], schi[0][2]) if x[0] == wanted]
    if len(fields) != 1:
        raise ValueError(f"expected one {wanted!r} field")
    return sinf[fields[0][1] : fields[0][2]]


def derive_work16(credential: bytes, sinf: bytes) -> bytes:
    name = _sinf_field(sinf, b"name").split(b"\0", 1)[0]
    iviv = _sinf_field(sinf, b"iviv")
    raw_priv = _sinf_field(sinf, b"priv")
    if len(raw_priv) not in (440, 448):
        raise ValueError("unsupported SINF priv-record length")
    if len(raw_priv) == 440:
        if raw_priv[-8:] != bytes(8):
            raise ValueError("invalid SINF priv-record trailer")
        raw_priv = raw_priv[:-8]
    if len(credential) != 16 or len(iviv) != 16:
        raise ValueError("invalid SINF priv-record dimensions")
    iv = hashlib.md5(name + iviv).digest()
    op = Cipher(algorithms.AES(_xor(credential, b"0" * 16)), modes.CBC(iv)).decryptor()
    clear = op.update(raw_priv) + op.finalize()
    if clear[:4] != b"itun" or clear[20:24] != b"key " or clear[44:48] != b"iviv":
        raise ValueError("credential does not decode this SINF priv record")
    return _xor(clear[24:40], WORK_MASK)


def arm64_supf_record_offset(supf: bytes, required_pages: int) -> int:
    if len(supf) < 12 or supf[0] not in (3, 5) or supf[1:4] not in (b"507", b"510", b"612"):
        raise ValueError("unsupported SUPF format")
    header_size = 32 if supf[0] == 3 else 12
    count = struct.unpack_from(">I", supf, 8)[0]
    if not 0 < count <= 16:
        raise ValueError("invalid SUPF architecture count")
    pos = 12
    for _ in range(count):
        if pos + 4 + header_size > len(supf):
            raise ValueError("truncated SUPF architecture header")
        length, cpu, subtype = struct.unpack_from(">III", supf, pos)
        if length < header_size or pos + 4 + length > len(supf):
            raise ValueError("invalid SUPF architecture length")
        pages = struct.unpack_from(">I", supf, pos + header_size)[0]
        if cpu == ARM64 and subtype == 0:
            if pages < required_pages or length < header_size + pages * 32:
                raise ValueError("SUPF arm64 page records are incomplete")
            return pos + 4 + header_size
        pos += length + 4
    raise ValueError("arm64 SUPF record missing")


def _high8_from_context_word(word: int) -> bytes:
    return (word ^ 0x2D43FBF6ED1B8833).to_bytes(8, "big")


def source_blocks(wrapped: bytes, absolute_index: int) -> tuple[bytes, bytes, bytes]:
    if len(wrapped) != 16 or not 0 <= absolute_index < 1 << 32:
        raise ValueError("invalid wrapped record or page index")
    context = CONTEXT_BASE ^ (absolute_index << 12)
    first = _xor(wrapped[8:16], CONSTANT[:8]) + _high8_from_context_word(context)
    second = _xor(wrapped, CONSTANT)
    third = (int.from_bytes(CONSTANT[:8], "big") ^ (absolute_index << 12)).to_bytes(
        8, "big"
    ) + _xor(wrapped[:8], CONSTANT[8:])
    return first, second, third


def _mix_round(before: list[int], selectors: bytes) -> list[int]:
    out = []
    for pair in range(4):
        a = before[selectors[pair * 2] - 0x36] ^ 0x18FB
        b = before[selectors[pair * 2 + 1] - 0x36] ^ 0x18FB
        mixed = a + b
        square = (mixed * mixed ^ ROUND_CONSTANTS[pair]) & MASK32
        low = ((0xCB61 - ((mixed >> 16) & 0xFFFF) ** 2) ^ square) & 0xFFFF
        out.append(low ^ 0x18FB)
        out.append((square >> 16) ^ 0x1E49)
    return out


def finish(state: bytes) -> bytes:
    if len(state) != 16:
        raise ValueError("finishing permutation requires 16 bytes")
    initial = [
        int.from_bytes(state[i : i + 2], "big") ^ 0x18FB for i in range(0, 16, 2)
    ]
    row = initial
    for selectors in ROUND_SELECTORS:
        row = _mix_round(row, selectors)
    final = []
    for j, selectors in enumerate(FINAL_SELECTORS):
        decoded = [row[i] ^ 0x18FB for i in selectors]
        left = decoded[0] | decoded[1] << 16
        right = decoded[2] | decoded[3] << 16
        x9 = ((left + right) & MASK32) ** 2 & MASK64
        x9 ^= 0x4F3DAC1F8847818E
        x19 = _FINAL_CONSTANTS[j] ^ x9
        x9 = x19 ^ (x9 >> 32)
        low = (x9 ^ 0xB4E4) & 0xFFFF
        high = ((x9 >> 16) ^ 0x4F3D ^ 0x18FB) & 0xFFFF
        final.extend((low, high))
    return b"".join(
        (a ^ b).to_bytes(2, "big") for a, b in zip(initial, final)
    )


def block_transform(source: bytes, work: bytes) -> bytes:
    """AES-128-ECB encrypt of ``source ^ CONSTANT`` under ``work ^ WORK_MASK``."""
    if len(source) != 16 or len(work) != 16:
        raise ValueError("block-transform inputs require 16 bytes")
    op = Cipher(algorithms.AES(_xor(work, WORK_MASK)), modes.ECB()).encryptor()
    return op.update(_xor(source, CONSTANT)) + op.finalize()


def derive_page_key(wrapped: bytes, absolute_index: int, work: bytes) -> bytes:
    a, b, c = (block_transform(s, work) for s in source_blocks(wrapped, absolute_index))
    return finish(_xor(finish(_xor(finish(a), b)), c))


def decrypt_binary(
    source: bytes, sinf: bytes, supf: bytes, credential: bytes
) -> tuple[bytes, int]:
    info = arm64_encryption_info(source)
    page_count = info.cryptsize // PAGE_SIZE
    record_start = arm64_supf_record_offset(supf, page_count)
    work = derive_work16(credential, sinf)
    result = bytearray(source)
    for local_page in range(page_count):
        record = supf[
            record_start + 32 * local_page : record_start + 32 * (local_page + 1)
        ]
        if len(record) != 32:
            raise ValueError("truncated SUPF page record")
        absolute_index = (info.base + info.cryptoff) // PAGE_SIZE + local_page
        key = derive_page_key(record[:16], absolute_index, work)
        start = info.base + info.cryptoff + PAGE_SIZE * local_page
        ciphertext = source[start : start + PAGE_SIZE]
        op = Cipher(algorithms.AES(key), modes.CBC(record[16:32])).decryptor()
        result[start : start + PAGE_SIZE] = op.update(ciphertext) + op.finalize()
    struct.pack_into("<I", result, info.cryptid_offset, 0)
    return bytes(result), page_count
