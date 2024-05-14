//
// Created by Mrack on 2024/5/6.
//

#include <dlfcn.h>
#include <jni.h>
#include <android/log.h>
#include "utils.h"
#include <thread>
#include <unistd.h>
#include <vector>
#include "dobby/dobby.h"
#include "json.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 56832

#define TAG "TInjectCore"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))

void *android_os_Process_setArg = nullptr;
void *selinux_android_setcontext = nullptr;
char *need_inject_pkg = nullptr;
char *need_inject_so = nullptr;

void send_msg() {
    int sockfd;
    struct sockaddr_in server_addr{};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct timeval timeout{};
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(1);
    }

    nlohmann::json j;
    j["pid"] = getpid();
    j["pkg"] = need_inject_pkg;
    j["so"] = need_inject_so;


    std::string s = j.dump();
    const char *message = s.c_str();

    size_t len = strlen(message);

    if (send(sockfd, &len, sizeof(size_t), 0) < 0) {
        perror("send");
        exit(1);
    }

    if (send(sockfd, message, strlen(message), 0) < 0) {
        perror("send");
        exit(1);
    }

    close(sockfd);
}

install_hook_name(selinux_android_setcontext, int, uid_t uid, bool isSystemServer, const char *seinfo,
                  const char *name) {
    int res = orig_selinux_android_setcontext(uid, isSystemServer, seinfo, name);
    if (need_inject_pkg != nullptr && need_inject_so != nullptr && strcmp(name, need_inject_pkg) == 0) {
        LOGD("pkgName: %s", name);
        void *handle = dlopen(need_inject_so, RTLD_NOW);
        if (handle == nullptr) {
            LOGE("dlopen failed: %s", dlerror());
            return res;
        } else {
            LOGD("inject so: %s", need_inject_so);
            send_msg();
        }
    }

    DobbyDestroy(selinux_android_setcontext);
    DobbyDestroy(android_os_Process_setArg);
    dlclose(dlopen(nullptr, RTLD_NOW));
    return res;
}

install_hook_name(android_os_Process_setArgV0, void, JNIEnv *env, jobject obj, jstring arg) {
    orig_android_os_Process_setArgV0(env, obj, arg);
    const char *pkgName = env->GetStringUTFChars(arg, nullptr);
    if (need_inject_pkg != nullptr && need_inject_so != nullptr && strcmp(pkgName, need_inject_pkg) == 0) {
        LOGD("pkgName: %s", pkgName);
        void *handle = dlopen(need_inject_so, RTLD_NOW);
        if (handle == nullptr) {
            LOGE("dlopen failed: %s", dlerror());
            return;
        } else {
            LOGD("inject so: %s", need_inject_so);
            send_msg();
        }
    }
    env->ReleaseStringUTFChars(arg, pkgName);
    DobbyDestroy(selinux_android_setcontext);
    DobbyDestroy(android_os_Process_setArg);
    dlclose(dlopen(nullptr, RTLD_NOW));
}

install_hook_name(fork, pid_t, void) {
    pid_t pid = orig_fork();
    if (pid == 0) {
        DobbyDestroy((void *) fork);
        LOGD("fork %d", getpid());
        android_os_Process_setArg = DobbySymbolResolver("libandroid_runtime.so",
                                                        "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring");
        if (android_os_Process_setArg) {
            install_hook_android_os_Process_setArgV0((void *) android_os_Process_setArg);
        } else {
            LOGE("android_os_Process_setArgV0 is null");
        }

        selinux_android_setcontext = DobbySymbolResolver("libselinux.so", "selinux_android_setcontext");
        if (selinux_android_setcontext) {
            install_hook_selinux_android_setcontext((void *) selinux_android_setcontext);
        } else {
            LOGE("android_os_Process_setArgV0 is null");
        }
    }
    return pid;
}

__attribute__ ((visibility ("default")))
extern "C"
void ainject(const char *pkg, const char *so_path) {
    need_inject_pkg = strdup(pkg);
    need_inject_so = strdup(so_path);
    LOGD("ainject: %s %s", need_inject_pkg, need_inject_so);
    install_hook_fork((void *) fork);
}

__attribute__ ((visibility ("default")))
extern "C"
void unload() {
    LOGD("unload");
    DobbyDestroy((void *) fork);
}


__attribute__((destructor()))
void destroy_globals() {
    LOGD("destroy_globals");
    DobbyDestroy((void *) fork);
}
