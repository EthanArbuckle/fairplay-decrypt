"""FairPlay IPA decryption and page-key derivation."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ARM64 = 0x0100000C
MASK32 = 0xFFFFFFFF
PAGE_SIZE = 4096
ROUND_SELECTORS = (
    ((0, 1), (2, 3), (4, 5), (6, 7)),
    ((2, 1), (0, 3), (4, 7), (6, 5)),
    ((2, 0), (4, 1), (6, 3), (7, 5)),
    ((1, 2), (4, 0), (7, 3), (5, 6)),
)
ROUND_CONSTANTS = (0x68547C2E, 0x7E05E1DE, 0xD495038B, 0x0AB24ADD)
FINAL_SELECTORS = ((0, 1, 2, 3), (0, 2, 4, 6), (0, 3, 5, 7), (4, 5, 6, 7))
FINAL_CONSTANTS = (0x5B7198C7, 0xEB5DE22C, 0x0F8AA8FA, 0xF6E1BB3F)


@dataclass(frozen=True)
class MachoInfo:
    base: int
    cryptoff: int
    cryptsize: int
    cryptid_offset: int
    subtype: int


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def _xor_int(lhs: Sequence[int], rhs: Sequence[int]) -> Sequence[int]:
    return [x ^ y for x, y in zip(lhs, rhs)]


def arm64_encryption_infos(data: bytes) -> list[MachoInfo]:
    if data[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", data, 4)[0]
        if not 0 < count <= 16 or 8 + count * 20 > len(data):
            raise ValueError("invalid FAT32 architecture table")
        entries = [struct.unpack_from(">IIIII", data, 8 + i * 20) for i in range(count)]
        arm = [
            (off, size, sub) for cpu, sub, off, size, _align in entries if cpu == ARM64
        ]
    elif data[:4] == b"\xca\xfe\xba\xbf":
        count = struct.unpack_from(">I", data, 4)[0]
        if not 0 < count <= 16 or 8 + count * 32 > len(data):
            raise ValueError("invalid FAT64 architecture table")
        entries = [
            struct.unpack_from(">IIQQII", data, 8 + i * 32) for i in range(count)
        ]
        arm = [
            (off, size, sub)
            for cpu, sub, off, size, _align, _reserved in entries
            if cpu == ARM64
        ]
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        arm = [(0, len(data), struct.unpack_from("<I", data, 8)[0])]
    else:
        raise ValueError("not a supported arm64 Mach-O")
    if not arm:
        raise ValueError("no arm64 slices found")
    infos = []
    for base, size, subtype in arm:
        info = _arm64_slice_info(data, base, size, subtype)
        if info is not None:
            infos.append(info)
    return infos


def _arm64_slice_info(
    data: bytes, base: int, slice_size: int, subtype: int
) -> MachoInfo | None:
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
    if pos != commands_end:
        raise ValueError("load command sizes do not match Mach-O header")
    if not found:
        return None
    if len(found) != 1:
        raise ValueError(f"expected one encryption command, found {len(found)}")
    cryptoff, cryptsize, cryptid, cryptid_offset = found[0]
    if cryptid == 0:
        return None
    if cryptid != 1 or cryptsize == 0 or cryptsize % PAGE_SIZE:
        raise ValueError(f"unsupported cryptid/size: {cryptid}, {cryptsize}")
    if cryptoff + cryptsize > slice_size or cryptid_offset >= base + cryptoff:
        raise ValueError("invalid encrypted region bounds")
    return MachoInfo(base, cryptoff, cryptsize, cryptid_offset, subtype)


def _children(data: bytes, start: int, end: int) -> Iterator[tuple[bytes, int, int]]:
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
    return clear[24:40]


def arm64_supf_record_offset(
    supf: bytes, required_pages: int, wanted_subtype: int
) -> int:
    if (
        len(supf) < 12
        or supf[0] not in (3, 5)
        or supf[1:4] not in (b"507", b"510", b"612")
    ):
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
        if cpu == ARM64 and subtype == wanted_subtype:
            if pages < required_pages or length < header_size + pages * 32:
                raise ValueError("SUPF arm64 page records are incomplete")
            return pos + 4 + header_size
        pos += length + 4
    raise ValueError("arm64 SUPF record missing")


def source_blocks(wrapped: bytes, absolute_index: int) -> tuple[bytes, bytes, bytes]:
    if len(wrapped) != 16 or not 0 <= absolute_index < 1 << 32:
        raise ValueError("invalid wrapped record or page index")
    page_offset = (absolute_index << 12).to_bytes(8, "big")
    first = wrapped[8:16] + page_offset
    second = wrapped
    third = page_offset + wrapped[:8]
    return first, second, third


def finish(state: Sequence[int]) -> Sequence[int]:
    # 16-bit
    src = state
    for selectors in ROUND_SELECTORS:
        dst: list[int] = []
        for pair, constant in zip(selectors, ROUND_CONSTANTS):
            mixed = src[pair[0]] + src[pair[1]]  # carry bit kept
            square = mixed * mixed
            x = (square & MASK32) ^ (mixed >> 16) ^ constant
            dst.extend((x & 0xFFFF, x >> 16))
        src = dst

    # 32-bit
    dst = []
    for quartet, constant in zip(FINAL_SELECTORS, FINAL_CONSTANTS):
        a = (src[quartet[1]] << 16) | src[quartet[0]]
        b = (src[quartet[3]] << 16) | src[quartet[2]]
        mixed = (a + b) & MASK32  # carry bit dropped
        square = mixed * mixed
        x = (square & MASK32) ^ (square >> 32) ^ constant
        dst.extend((x & 0xFFFF, x >> 16))

    return _xor_int(state, dst)


def block_transform(source: bytes, work: bytes) -> bytes:
    """AES-128-ECB encrypt of ``source`` block under ``work``."""
    if len(source) != 16 or len(work) != 16:
        raise ValueError("block-transform inputs require 16 bytes")
    op = Cipher(algorithms.AES(work), modes.ECB()).encryptor()
    return op.update(source) + op.finalize()


def derive_page_key(wrapped: bytes, absolute_index: int, work: bytes) -> bytes:
    a, b, c = (
        struct.unpack(">8H", block_transform(s, work))
        for s in source_blocks(wrapped, absolute_index)
    )
    return struct.pack(">8H", *finish(_xor_int(finish(_xor_int(finish(a), b)), c)))


def decrypt_binary(
    source: bytes, sinf: bytes, supf: bytes, credential: bytes
) -> tuple[bytes, int]:
    infos = arm64_encryption_infos(source)
    work = derive_work16(credential, sinf)
    result = bytearray(source)
    total_pages = 0
    for info in infos:
        page_count = info.cryptsize // PAGE_SIZE
        record_start = arm64_supf_record_offset(supf, page_count, info.subtype)
        total_pages += page_count
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
    return bytes(result), total_pages
