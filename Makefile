.DEFAULT_GOAL := all

PY_FILES := core.py decrypt.py credential-retrieval/retrieve.py credential-retrieval/native_ssh.py tests/test_retrieve.py
RUFF := uvx --from ruff==0.14.3 ruff
BLACK := uvx --from black==26.10.1 black
MYPY := uvx --from mypy==2.4.0 --with-requirements requirements.txt mypy

.PHONY: all credential-bundle lint lint-ruff lint-black lint-mypy format

all:
ifeq ($(shell uname -s),Darwin)
all: credential-bundle
endif

credential-bundle:
	@$(MAKE) --no-print-directory -C credential-retrieval

lint: lint-ruff lint-black lint-mypy

lint-ruff:
	@$(RUFF) check $(PY_FILES) || { printf '%s\n' "Ruff failed. Run 'make format' to apply available fixes, then 'make lint'." >&2; exit 1; }

lint-black:
	@$(BLACK) --check $(PY_FILES) || { printf '%s\n' "Black failed. Run 'make format', then 'make lint'." >&2; exit 1; }

lint-mypy:
	@$(MYPY) $(PY_FILES) || { printf '%s\n' "mypy failed. Fix the reported type errors, then run 'make lint'." >&2; exit 1; }

format:
	@$(RUFF) check --fix $(PY_FILES)
	@$(BLACK) $(PY_FILES)
