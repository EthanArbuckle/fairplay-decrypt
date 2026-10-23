.DEFAULT_GOAL := all

.PHONY: all credential-bundle

all: transform
ifeq ($(shell uname -s),Darwin)
all: credential-bundle
endif

transform: transform.c
	$(CC) -std=c11 -O2 -o $@ $<

credential-bundle:
	@$(MAKE) --no-print-directory -C credential-retrieval

DEVICE_FILES := credential.ios driver.ios trigger.ios static-key-table.bin core4-word-table.bin
PYINSTALLER := python3 -m PyInstaller --onefile --noconfirm --clean --distpath dist --workpath build/pyinstaller --specpath build/pyinstaller

.PHONY: dist
dist: all
	$(PYINSTALLER) --name fairplay-decrypt --add-binary "$(CURDIR)/transform:." --add-data "$(CURDIR)/transform_const_data.bin:." decrypt.py
ifeq ($(shell uname -s),Darwin)
	mkdir -p build
	COPYFILE_DISABLE=1 tar -C credential-retrieval/build/bundle -cf build/bundle.tar $(DEVICE_FILES)
	$(PYINSTALLER) --name fairplay-credential --paths credential-retrieval --add-data "$(CURDIR)/build/bundle.tar:." credential-retrieval/retrieve.py
endif
