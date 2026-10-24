.DEFAULT_GOAL := all

.PHONY: all credential-bundle

all:
ifeq ($(shell uname -s),Darwin)
all: credential-bundle
endif

credential-bundle:
	@$(MAKE) --no-print-directory -C credential-retrieval
