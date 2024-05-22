//
// Created by Mrack on 2024/5/6.
//
#include <android/log.h>
#include "utils.h"
#include "dobby/dobby.h"
#include <thread>
#include <unistd.h>

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

enum class TraceOutputMode {
    kFile,
    kDDMS,
    kStreaming
};
enum class TraceMode {
    kMethodTracing,
    kSampling
};

enum TraceFlag {
    kTraceCountAllocs = 0x001,
    kTraceClockSourceWallClock = 0x010,
    kTraceClockSourceThreadCpu = 0x100,
};

__attribute__((constructor()))
void initialize_globals() {
    LOGD("initialize_globals_test");
    hook_module_load();

    return;

    std::thread([] {
        sleep(5);
        const char *art = find_path_from_maps("libart.so");
        auto start_ = reinterpret_cast<void (*)(const char *, size_t, int, TraceOutputMode, TraceMode, int)>(
                get_address_from_module(art, "_ZN3art5Trace5StartEPKcmiNS0_15TraceOutputModeENS0_9TraceModeEi"));
        auto shutdown_ = reinterpret_cast<void (*)()>(
                get_address_from_module(art, "_ZN3art5Trace8ShutdownEv"));
        JavaEnv env;
        if (env.isNull()) {
            LOGD("env is null");
            return;
        }
        LOGD("start_: %p, shutdown_: %p", start_, shutdown_);
        start_("/data/data/com.google.android.youtube/trace.txt", 8 * 1024 * 1024, 0, TraceOutputMode::kFile,
               TraceMode::kMethodTracing, 0);
        LOGD("start trace");
        usleep(5 * 1000 * 1000);
        shutdown_();
        LOGD("shutdown trace");
    }).detach();

}


__attribute__((destructor()))
void destroy_globals() {
    LOGD("destroy_globals_test");
}
