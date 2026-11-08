.DELETE_ON_ERROR:

BUILD_DIR := build
BUNDLE_DIR := $(BUILD_DIR)/bundle
COMMON_FLAGS := -arch arm64 -miphoneos-version-min=10.0 -O2 -Wall -Wextra -Werror
DEVICE_PROGRAMS := credential.ios driver.ios trigger.ios arcade-capture.ios
DEVICE_DATA := static-key-table.bin core4-word-table.bin

.PHONY: all bundle

all: bundle

bundle: $(addprefix $(BUNDLE_DIR)/,$(DEVICE_PROGRAMS) $(DEVICE_DATA))

$(BUILD_DIR) $(BUNDLE_DIR):
	mkdir -p "$@"

$(BUILD_DIR)/credential.ios: Makefile credential/credential.c credential/observer.c credential/observer.h credential/finalizer.c credential/finalizer.h credential/selector_native.c credential/selector_native.h credential/core4_native.c credential/core4_native.h credential/core4_digest.c credential/core4_digest.h credential/core4_aes.c credential/core4_aes.h credential/core4_finish.c credential/core4_finish.h credential/core4_contexts.c credential/core4_contexts.h credential/core4_tables.inc credential/credential.entitlements.plist | $(BUILD_DIR)
	xcrun --sdk iphoneos clang $(COMMON_FLAGS) -std=c11 -fwrapv -fno-strict-aliasing -Wno-bitwise-op-parentheses -Wno-shift-op-parentheses credential/credential.c credential/observer.c credential/finalizer.c credential/selector_native.c credential/core4_native.c credential/core4_digest.c credential/core4_aes.c credential/core4_finish.c credential/core4_contexts.c -framework CoreFoundation -framework IOKit -o "$@"
	ldid -Scredential/credential.entitlements.plist "$@"

$(BUILD_DIR)/driver.ios: Makefile driver/driver.c driver/driver.entitlements.plist | $(BUILD_DIR)
	xcrun --sdk iphoneos clang $(COMMON_FLAGS) driver/driver.c -framework IOKit -o "$@"
	ldid -Sdriver/driver.entitlements.plist "$@"

$(BUILD_DIR)/trigger.ios: Makefile trigger/trigger.c trigger/trigger.entitlements.plist | $(BUILD_DIR)
	xcrun --sdk iphoneos clang $(COMMON_FLAGS) -std=c11 trigger/trigger.c -o "$@"
	ldid -Strigger/trigger.entitlements.plist "$@"

$(BUILD_DIR)/arcade-capture.ios: Makefile arcade-capture/arcade_capture.c arcade-capture/arcade-capture.entitlements.plist credential/observer.c credential/observer.h | $(BUILD_DIR)
	xcrun --sdk iphoneos clang $(COMMON_FLAGS) -std=c11 arcade-capture/arcade_capture.c credential/observer.c -framework IOKit -o "$@"
	ldid -Sarcade-capture/arcade-capture.entitlements.plist "$@"

$(BUNDLE_DIR)/%: $(BUILD_DIR)/% | $(BUNDLE_DIR)
	cp "$<" "$@"

$(BUNDLE_DIR)/static-key-table.bin: credential/static-key-table.bin | $(BUNDLE_DIR)
	cp "$<" "$@"

$(BUNDLE_DIR)/core4-word-table.bin: credential/core4-word-table.bin | $(BUNDLE_DIR)
	cp "$<" "$@"
