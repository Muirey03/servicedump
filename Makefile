ARCHS = arm64 armv7

include $(THEOS)/makefiles/common.mk

TOOL_NAME = servicedump
servicedump_FILES = main.mm
servicedump_CODESIGN_FLAGS = -Sent.xml
servicedump_CFLAGS = -fobjc-arc -Wno-unguarded-availability-new

include $(THEOS_MAKE_PATH)/tool.mk
