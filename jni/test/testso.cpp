//
// Created by Mrack on 2024/5/6.
//
#include <android/log.h>
#include "utils.h"
#include "dobby/dobby.h"

#define TAG "TESTSO"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))


install_hook_name(android_dlopen_ext, void *, const char *filename, int flags,
                  const void *extinfo) {
    void *ret = orig_android_dlopen_ext(filename, flags, extinfo);
    LOGD("load module: %s, flags: %d, extinfo: %p, ret: %p", filename, flags, extinfo, ret);
    return ret;
}

void hook_module_load() {
    void *address = get_address_from_module(get_linker_path(), "android_dlopen_ext");
    if (address != nullptr) {
        install_hook_android_dlopen_ext(address);
    } else {
        LOGD("hook_module_load: android_dlopen_ext not found");
    }
}

__attribute__((constructor()))
void initialize_globals() {
    LOGD("initialize_globals_test");
    hook_module_load();
}


__attribute__((destructor()))
void destroy_globals() {
    LOGD("destroy_globals_test");
}
