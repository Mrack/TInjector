//
// Created by Mrack on 2024/5/22.
//

#include "hide.h"
#include "utils.h"
#include <sys/mman.h>

void *solist_get_head() {
    static void *(*solist_get_head_sym)();
    if (solist_get_head_sym == nullptr) {
        solist_get_head_sym = ((void *(*)()) get_address_from_module(
                get_linker_path(), "solist_get_head"));
    }
    return solist_get_head_sym();
}

void *solist_get_somain() {
    static void *(*solist_get_somain_sym)();
    if (solist_get_somain_sym == nullptr) {
        solist_get_somain_sym = ((void *(*)()) get_address_from_module(
                get_linker_path(), "solist_get_somain"));
    }
    return solist_get_somain_sym();
}

bool solist_remove_soinfo(void *soinfo) {
    static bool (*solist_remove_sym)(void *);
    if (solist_remove_sym == nullptr) {
        solist_remove_sym = ((bool (*)(void *)) get_address_from_module(
                get_linker_path(), "solist_remove_soinfo"));
    }
    return solist_remove_sym(soinfo);
}

const char *get_realpath(void *soinfo) {
    static const char *(*soinfo_get_realpath_sym)(void *);
    if (soinfo_get_realpath_sym == nullptr) {
        soinfo_get_realpath_sym = ((const char *(*)(void *)) get_address_from_module(
                get_linker_path(), "__dl__ZNK6soinfo12get_realpathEv"));
    }
    return soinfo_get_realpath_sym(soinfo);
}

class ProtectedDataGuard {
public:
    static void init() {
        ProtectedDataGuard::ctor = (FuncType *) get_address_from_module(
                get_linker_path(), "__dl__ZN18ProtectedDataGuardC2Ev");
        ProtectedDataGuard::dtor = (FuncType *) get_address_from_module(
                get_linker_path(), "__dl__ZN18ProtectedDataGuardD2Ev");
    }

    ProtectedDataGuard() {
        if (!(ctor && dtor)) {
            init();
        }
        if (ctor) {
            ctor(this);
        }
    }

    ~ProtectedDataGuard() {
        if (dtor) {
            dtor(this);
        }
    }

private:
    using FuncType = void(void *);
    static FuncType *ctor;
    static FuncType *dtor;
};

ProtectedDataGuard::FuncType *ProtectedDataGuard::ctor = nullptr;
ProtectedDataGuard::FuncType *ProtectedDataGuard::dtor = nullptr;


void print_soinfos() {
    static uintptr_t *solist_head = NULL;
    if (!solist_head)
        solist_head = (uintptr_t *) solist_get_head();

    static uintptr_t somain = 0;

    if (!somain)
        somain = (uintptr_t) solist_get_somain();

    int offset_solist_next = 0;
    for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
        if (*(uintptr_t *) ((uintptr_t) solist_head + i * sizeof(void *)) == somain) {
            offset_solist_next = i * sizeof(void *);
            break;
        }
    }

    auto cur = *(uintptr_t *) ((uintptr_t) solist_head + offset_solist_next);
    while (cur) {
        const char *realpath = get_realpath((void *) cur);
        if (realpath == nullptr) {
            continue;
        }
        LOGD("realpath: %s", realpath);
        cur = *(uintptr_t *) ((uintptr_t) cur + offset_solist_next);
    }
}

void hide_soinfo(const std::string &name) {
    static uintptr_t *solist_head = NULL;
    if (!solist_head)
        solist_head = (uintptr_t *) solist_get_head();

    static uintptr_t somain = 0;

    if (!somain)
        somain = (uintptr_t) solist_get_somain();

    int offset_solist_next = 0;
    for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
        if (*(uintptr_t *) ((uintptr_t) solist_head + i * sizeof(void *)) == somain) {
            offset_solist_next = i * sizeof(void *);
            break;
        }
    }

    uintptr_t so_info = 0;
    auto cur = *(uintptr_t *) ((uintptr_t) solist_head + offset_solist_next);
    while (cur) {
        const char *realpath = get_realpath((void *) cur);
        if (realpath == nullptr) {
            continue;
        }
        if (strstr(realpath, name.c_str()) != nullptr) {
            LOGD("hide realpath: %s, so_info: %p", realpath, (void *) cur);
            so_info = cur;
            break;
        }
        cur = *(uintptr_t *) ((uintptr_t) cur + offset_solist_next);
    }
    if (so_info != 0) {
        ProtectedDataGuard guard;
        solist_remove_soinfo((void *) so_info);
    }

}