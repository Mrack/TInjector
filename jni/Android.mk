LOCAL_PATH := $(call my-dir)
MAIN_LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tinjector
LOCAL_SRC_FILES := main.cpp
LOCAL_C_INCLUDES := $(MAIN_LOCAL_PATH)/core
LOCAL_CPPFLAGS := -Os -std=c++17 -Werror=format -fdata-sections -ffunction-sections -fvisibility=hidden -Wl,--exclude-libs,ALL
LOCAL_LDLIBS := -ldl -llog
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := local_dobby
LOCAL_SRC_FILES := core/$(TARGET_ARCH_ABI)/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := testso
LOCAL_SRC_FILES := test/testso.cpp test/utils.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/core
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := local_dobby
LOCAL_CPPFLAGS := -Os -std=c++17 -Werror=format -fdata-sections -ffunction-sections -fvisibility=hidden -Wl,--exclude-libs,ALL
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := tcore
LOCAL_SRC_FILES := core/core.cpp core/utils.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/core $(LOCAL_PATH)
LOCAL_CPPFLAGS := -Os -std=c++17 -Werror=format -fdata-sections -ffunction-sections -fvisibility=hidden -Wl,--exclude-libs,ALL
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := local_dobby
include $(BUILD_SHARED_LIBRARY)

