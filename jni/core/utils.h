//
// Created by Mrack on 2024/5/9.
//

#ifndef TINYINJECT_UTILS_H
#define TINYINJECT_UTILS_H

#include <string>
#include <android/log.h>
#include <jni.h>


#define TAG "TInjectCore"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))

#define ANDROID_O 26
#define ANDROID_O2 27
#define ANDROID_P 28
#define ANDROID_Q 29
#define ANDROID_R 30
#define ANDROID_S 31
static int SDK_INT = -1;

extern JavaVM *gVm;

const char *get_data_path(jobject context);

int get_sdk_level();

char *get_linker_path();

std::pair<size_t, size_t> find_info_from_maps(const char *soname);

const char *find_path_from_maps(const char *soname);

int boyer_moore_search(u_char *haystack, size_t haystackLen, u_char *needle, size_t needleLen);

int search_hex(u_char *haystack, size_t haystackLen, const char *needle);

void *get_address_from_module(const char *module_path, const char *symbol_name);

std::string hexdump(const uint8_t *buf, size_t len);

char *get_package_name();

class JavaEnv {
public:
    JavaEnv() {
        if (gVm == nullptr) {
            jsize num_vms;
            auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) get_address_from_module(
                    find_path_from_maps("libart.so"), "GetCreatedJavaVMs");
            jint status = JNI_GetCreatedJavaVMs(&gVm, 1, &num_vms);
            if (status != JNI_OK || num_vms == 0) {
                gVm = nullptr;
                env = nullptr;
                return;
            }
        }

        int state = gVm->GetEnv((void **) &env, JNI_VERSION_1_6);
        if (state == JNI_EDETACHED) {
            if (JNI_OK == gVm->AttachCurrentThread(&env, NULL)) {
                attach = true;
            } else {
                env = nullptr;
            }
        } else if (state == JNI_EVERSION) {
            env = nullptr;
        }


    }

    ~JavaEnv() {
        if (gVm != nullptr && attach) {
            gVm->DetachCurrentThread();
        }
    }

    JNIEnv *operator->() const {
        return env;
    }

    bool isNull() const {
        return env == nullptr;
    }

    JNIEnv *env;
    bool attach = false;
};

#endif //TINYINJECT_UTILS_H
