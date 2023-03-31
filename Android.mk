LOCAL_PATH := $(call my-dir)

## include variants like TA_DEV_KIT_DIR
## and OPTEE_BIN
INCLUDE_FOR_BUILD_TA := false
include $(BUILD_OPTEE_MK)
INCLUDE_FOR_BUILD_TA :=

VERSION = $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)

# TA_DEV_KIT_DIR must be set to non-empty value to
# avoid the Android build scripts complaining about
# includes pointing outside the Android source tree.
# This var is expected to be set when OPTEE OS built.
# We set the default value to an invalid path.
TA_DEV_KIT_DIR ?= ../invalid_include_path

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk
include $(LOCAL_PATH)/scripts/common.mk

################################################################################
# Build xtest                                                                  #
################################################################################
include $(CLEAR_VARS)
LOCAL_MODULE := xtest
LOCAL_VENDOR_MODULE := true
LOCAL_SHARED_LIBRARIES := libteec

TA_DIR ?= /vendor/lib/optee_armtz

srcs := regression_1000.c

ifeq ($(CFG_GP_SOCKETS),y)
srcs += regression_2000.c \
	sock_server.c \
	rand_stream.c
endif

srcs +=	adbg/src/adbg_case.c \
	adbg/src/adbg_enum.c \
	adbg/src/adbg_expect.c \
	adbg/src/adbg_log.c \
	adbg/src/adbg_run.c \
	adbg/src/security_utils_hex.c \
	asym_perf.c \
	benchmark_1000.c \
	benchmark_2000.c \
	clear_storage.c \
	regression_4000.c \
	regression_4100.c \
	regression_5000.c \
	regression_6000.c \
	regression_8000.c \
	regression_8100.c \
	hash_perf.c \
	install_ta.c \
	stats.c \
	symm_cipher_perf.c \
	xtest_helpers.c \
	xtest_main.c \
	xtest_test.c \
	xtest_uuid_helpers.c

ifeq ($(CFG_SECURE_PARTITION)-$(CFG_SPMC_TESTS),y-y)
srcs += ffa_spmc_1000.c
endif

ifeq ($(CFG_SECURE_DATA_PATH),y)
srcs += sdp_basic.c
endif

ifeq ($(CFG_PKCS11_TA),y)
srcs += pkcs11_1000.c
LOCAL_CFLAGS += -DCFG_PKCS11_TA
LOCAL_SHARED_LIBRARIES += libckteec
endif

define my-embed-file
$(TARGET_OUT_HEADERS)/$(1).h: $(LOCAL_PATH)/$(2)
	@echo '  GEN     $$@'
	@$(PYTHON3) $(LOCAL_PATH)/scripts/file_to_c.py --inf $$< --out $$@ --name $(1)

LOCAL_ADDITIONAL_DEPENDENCIES += $(TARGET_OUT_HEADERS)/$(1).h

endef

$(eval $(call my-embed-file,regression_8100_ca_crt,cert/ca.crt))
$(eval $(call my-embed-file,regression_8100_mid_crt,cert/mid.crt))
$(eval $(call my-embed-file,regression_8100_my_crt,cert/my.crt))
$(eval $(call my-embed-file,regression_8100_my_csr,cert/my.csr))

LOCAL_SRC_FILES := $(patsubst %,host/xtest/%,$(srcs))

LOCAL_C_INCLUDES += $(LOCAL_PATH)/host/xtest \
		$(LOCAL_PATH)/host/xtest/adbg/include \
		$(LOCAL_PATH)/host/xtest/include/uapi \
		$(LOCAL_PATH)/ta/include \
		$(LOCAL_PATH)/ta/supp_plugin/include \
		$(LOCAL_PATH)/ta/create_fail_test/include \
		$(LOCAL_PATH)/ta/crypt/include \
		$(LOCAL_PATH)/ta/enc_fs/include \
		$(LOCAL_PATH)/ta/os_test/include \
		$(LOCAL_PATH)/ta/rpc_test/include \
		$(LOCAL_PATH)/ta/sims/include \
		$(LOCAL_PATH)/ta/miss/include \
		$(LOCAL_PATH)/ta/sims_keepalive/include \
		$(LOCAL_PATH)/ta/storage_benchmark/include \
		$(LOCAL_PATH)/ta/concurrent/include \
		$(LOCAL_PATH)/ta/concurrent_large/include \
		$(LOCAL_PATH)/ta/crypto_perf/include \
		$(LOCAL_PATH)/ta/socket/include \
		$(LOCAL_PATH)/ta/sdp_basic/include \
		$(LOCAL_PATH)/ta/tpm_log_test/include \
		$(LOCAL_PATH)/ta/large/include \
		$(LOCAL_PATH)/ta/bti_test/include \
		$(LOCAL_PATH)/ta/subkey1/include \
		$(LOCAL_PATH)/ta/subkey2/include \
		$(LOCAL_PATH)/host/supp_plugin/include

# Include configuration file generated by OP-TEE OS (CFG_* macros)
LOCAL_CFLAGS += -I $(TA_DEV_KIT_DIR)/host_include -include conf.h
LOCAL_CFLAGS += -pthread
LOCAL_CFLAGS += -g3
LOCAL_CFLAGS += -Wno-missing-field-initializers -Wno-format-zero-length
LOCAL_CFLAGS += -Wno-unused-parameter

ifneq ($(TA_DIR),)
LOCAL_CFLAGS += -DTA_DIR=\"$(TA_DIR)\"
endif

## $(OPTEE_BIN) is the path of tee.bin like
## out/target/product/hikey/optee/arm-plat-hikey/core/tee.bin
## it will be generated after build the optee_os with target BUILD_OPTEE_OS
## which is defined in the common ta build mk file included before,
LOCAL_ADDITIONAL_DEPENDENCIES += $(OPTEE_BIN)

include $(BUILD_EXECUTABLE)

################################################################################
# Build tee-supplicant test plugin                                             #
################################################################################
include $(CLEAR_VARS)

PLUGIN_UUID = f07bfc66-958c-4a15-99c0-260e4e7375dd

PLUGIN                  = $(PLUGIN_UUID).plugin
PLUGIN_INCLUDES_DIR     = $(LOCAL_PATH)/host/supp_plugin/include

LOCAL_MODULE := $(PLUGIN)
LOCAL_MODULE_RELATIVE_PATH := tee-supplicant/plugins
LOCAL_VENDOR_MODULE := true
# below is needed to locate optee_client exported headers
LOCAL_SHARED_LIBRARIES := libteec

LOCAL_SRC_FILES += host/supp_plugin/test_supp_plugin.c
LOCAL_C_INCLUDES += $(PLUGIN_INCLUDES_DIR)
LOCAL_CFLAGS += -Wno-unused-parameter

$(info $$LOCAL_SRC_FILES = ${LOCAL_SRC_FILES})

LOCAL_MODULE_TAGS := optional

# Build the 32-bit and 64-bit versions.
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64

include $(BUILD_SHARED_LIBRARY)

################################################################################
# Build TAs                                                                    #
################################################################################
include $(LOCAL_PATH)/ta/Android.mk
