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
#include <set>
#include "dobby/dobby.h"
#include "json.hpp"
#include "hide.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 56832

#define HANDLE_EINTR(x) ({ \
    int eintr_count = 0;  \
    decltype(x) __result; \
    do { \
        __result = (x); \
    } while (__result == -1 && errno == EINTR && eintr_count++ < 100); \
    __result; \
})

std::set<pid_t> hookedpids;
void *android_os_Process_setArg = nullptr;
void *selinux_android_setcontext = nullptr;
char *need_inject_pkg = nullptr;
char *need_inject_so = nullptr;
uid_t need_inject_uid = 0;
bool is_hide = false;
bool is_inject_all = false;

void send_msg(const char* name) {
    int sockfd;
    struct sockaddr_in server_addr{};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOGD("%s", strerror(errno));
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
        LOGD("inet_pton: %s", strerror(errno));
        exit(1);
    }

    if (HANDLE_EINTR(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
        LOGD("connect: %s", strerror(errno));
        exit(1);
    }

    nlohmann::json j;
    j["pid"] = getpid();
    j["pkg"] = name;
    j["so"] = need_inject_so;
    j["uid"] = need_inject_uid;


    std::string s = j.dump();
    const char *message = s.c_str();
    // the message is so short to send the length
    // size_t len = strlen(message);

    // if (HANDLE_EINTR(send(sockfd, &len, sizeof(size_t), 0)) < 0) {
    //     LOGD("send: %s", strerror(errno));
    //     exit(1);
    // }

    if (HANDLE_EINTR(send(sockfd, message, strlen(message), 0)) < 0) {
        LOGD("send: %s", strerror(errno));
        exit(1);
    }

    close(sockfd);
}

void unhookall() {
    DobbyDestroy((void *) fork);
    DobbyDestroy((void *) vfork);

    DobbyDestroy(selinux_android_setcontext);
    DobbyDestroy(android_os_Process_setArg);
}

void unhookfunc() {
    DobbyDestroy(selinux_android_setcontext);
    DobbyDestroy(android_os_Process_setArg);
}

bool setenforce(bool value) {
    int ret = system(value ? "setenforce 1" : "setenforce 0");
    return ret == 0;
}


install_hook_name(selinux_android_setcontext, int, uid_t uid, bool isSystemServer, const char *seinfo,
                  const char *name) {
    LOGD("selinux_android_setcontext %s", name);
    int res = orig_selinux_android_setcontext(uid, isSystemServer, seinfo, name);
    if (need_inject_pkg != nullptr && need_inject_so != nullptr && getuid() == need_inject_uid && ((!is_inject_all && strcmp(name, need_inject_pkg) == 0) || is_inject_all)) {
        LOGD("pkgName: %s", name);
        unhookfunc();
        void *handle = dlopen(need_inject_so, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
        if (handle == nullptr) {
            LOGE("dlopen failed: %s", dlerror());
        } else {
            LOGD("inject so: %s", need_inject_so);
            send_msg(name);
            if (is_hide) {
                hide_soinfo(need_inject_so);
                print_soinfos();
            }
        }
    }
    dlclose(dlopen(nullptr, RTLD_NOW));
    if (is_hide) {
        hide_soinfo("libtcore.so");
        print_soinfos();
    }
    return res;
}

install_hook_name(android_os_Process_setArgV0, void, JNIEnv *env, jobject obj, jstring arg) {
    const char *c_arg = env->GetStringUTFChars(arg, nullptr);
    LOGD("android_os_Process_setArgV0 %s", c_arg);
    orig_android_os_Process_setArgV0(env, obj, arg);
    const char *pkgName = env->GetStringUTFChars(arg, nullptr);
    if (need_inject_pkg != nullptr && need_inject_so != nullptr && getuid() == need_inject_uid && ((!is_inject_all && strcmp(pkgName, need_inject_pkg) == 0) || is_inject_all)) {
        LOGD("pkgName: %s", pkgName);
        unhookfunc();
        void *handle = dlopen(need_inject_so, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
        if (handle == nullptr) {
            LOGE("dlopen failed: %s", dlerror());
        } else {
            LOGD("inject so: %s", need_inject_so);
            send_msg(pkgName);
            if (is_hide) {
                hide_soinfo(need_inject_so);
                print_soinfos();
            }
        }
    }
    env->ReleaseStringUTFChars(arg, pkgName);
    dlclose(dlopen(nullptr, RTLD_NOW));
    if (is_hide) {
        hide_soinfo("libtcore.so");
        print_soinfos();
    }
}

install_hook_name(fork, pid_t, void) {
    pid_t pid = orig_fork();
    if (pid == 0) {
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
            LOGE("selinux_android_setcontext is null");
        }
    }
    return pid;
}


install_hook_name(vfork, pid_t, void) {
    LOGD("vfork");
    return fake_fork();
}

__attribute__ ((visibility ("default")))
extern "C"
void ainject(const char *pkg, const char *so_path, const uid_t* uid) {
    need_inject_pkg = strdup(pkg);
    need_inject_so = strdup(so_path);
    need_inject_uid = *uid;
    is_hide = false;
    LOGD("ainject: %s %s %d", need_inject_pkg, need_inject_so, need_inject_uid);
    char *byte = reinterpret_cast<char *>(fork);
    if (byte[1] == 0x00 && byte[2] == 0x00 && byte[3] == 0x58 && byte[4] == 0x00 &&
        byte[5] == 0x02 && byte[6] == 0x1f && byte[7] == 0xd6) {
        LOGD("fork is hooked");
        return;
    }
    install_hook_fork((void *) fork);
    install_hook_vfork((void *) vfork);
}

__attribute__ ((visibility ("default")))
extern "C"
void enable_hide() {
    is_hide = true;
    LOGD("hide soinfo enabled");
}

__attribute__ ((visibility ("default")))
extern "C"
void enable_inject_all_proc() {
    is_inject_all = true;
}

__attribute__ ((visibility ("default")))
extern "C"
void unload() {
    LOGD("unload");
    unhookall();
    setenforce(true);
}


__attribute__((destructor()))
void destroy_globals() {
    LOGD("destroy_globals");
    unhookall();
}
