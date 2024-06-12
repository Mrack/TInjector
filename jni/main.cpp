//
// Created by Mrack on 2024/5/14.
//

#include "android/log.h"
#include <dirent.h>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <elf.h>
#include <dlfcn.h>
#include <linux/uio.h>
#include <cstdlib>
#include <vector>
#include <cerrno>
#include <unistd.h>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <future>
#include "core/json.hpp"

#define PORT 56832

#if defined(__aarch64__)
#define REGS_ARG_NUM    8
#define pt_regs user_regs_struct
#define uregs regs
#define ARM_sp sp
#define ARM_lr uregs[30]
#define ARM_pc pc
#define ARM_cpsr pstate
#elif defined(__arm__)
#define REGS_ARG_NUM    4
#else
#error "unsupported architecture"
#endif

#define TAG "TInject"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGE(...) do { fprintf(stderr, TAG ": " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define LOGI(...) do { printf(TAG ": " __VA_ARGS__); printf("\n"); } while (0)
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__))


#define HANDLE_EINTR(x) ({ \
    int eintr_count = 0;  \
    decltype(x) __result; \
    do { \
        __result = (x); \
    } while (__result == -1 && errno == EINTR && eintr_count++ < 20); \
    __result; \
})


int g_pid = -1;
const char *g_so_path = nullptr;
bool g_hide = false;
bool g_hide_beta = false;
bool g_spawn = false;
const char *g_package_name = nullptr;

long get_module_base(pid_t pid, const char *module_name) {
    long base_addr_long = 0;
    char *file_name = (char *) calloc(50, sizeof(char));
    if (pid == -1) {
        snprintf(file_name, 50, "/proc/self/maps");
    } else {
        snprintf(file_name, 50, "/proc/%d/maps", pid);
    }
    FILE *fp = fopen(file_name, "r");
    free(file_name);
    char line[512];
    if (fp != nullptr) {
        while (fgets(line, 512, fp) != nullptr) {
            if (strstr(line, module_name)) {
                char *p = strtok(line, "-");
                base_addr_long = strtoul(p, nullptr, 16);
                break;
            }
        }
        fclose(fp);
    }
    return base_addr_long;
}

const char *get_module_name(pid_t pid, uintptr_t addr) {
    char filepath[256];

    if (pid == -1) {
        snprintf(filepath, sizeof(filepath), "/proc/self/maps");
    } else {
        snprintf(filepath, sizeof(filepath), "/proc/%d/maps", pid);
    }

    FILE *mapsFile = fopen(filepath, "r");
    if (!mapsFile) {
        return "";
    }

    char line[1024];
    while (fgets(line, sizeof(line), mapsFile)) {
        uintptr_t startAddr, endAddr;
        sscanf(line, "%lx-%lx", &startAddr, &endAddr);

        if (addr >= startAddr && addr <= endAddr) {
            char *libPath = strchr(line, '/');
            if (libPath) {
                char *newline = strchr(libPath, '\n');
                if (newline) {
                    *newline = '\0';
                }
                fclose(mapsFile);
                return strdup(libPath);
            }
        }
    }

    fclose(mapsFile);
    return "";
}

long get_remote_addr(int pid, void *func) {
    const char *module = get_module_name(-1, (uintptr_t) func);
    long local_base = get_module_base(-1, module);
    long remote_base = get_module_base(pid, module);
    long remote_addr = (long) func - local_base + remote_base;

    LOGD("module: %s, local_base: %lx, remote_base: %lx", module, local_base, remote_base);

    if (!local_base || !remote_base) {
        LOGE("get module base failed.");
        exit(-1);
    }
    return remote_addr;
}


bool setenforce(bool value) {
    int ret = system(value ? "setenforce 1" : "setenforce 0");
    return ret == 0;
}

int get_pid(const char *process_name) {
    DIR *dir = opendir("/proc");
    dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid != 0) {
            char path[256] = {0};
            snprintf(path, 256, "/proc/%d/cmdline", pid);
            FILE *fp = fopen(path, "r");
            char temp_name[256];
            if (fp != nullptr) {
                fgets(temp_name, 256, fp);
                fclose(fp);
                char *name = strrchr(temp_name, '/');
                if (!name) {
                    name = temp_name;
                } else {
                    name++;
                }
                if (strcmp(process_name, name) == 0) {
                    return pid;
                }
            }
        }
    }
    return -1;
}


long xptrace(int __request, ...) {
    va_list args;
    va_start(args, __request);
    long result = ptrace(__request, va_arg(args, pid_t), va_arg(args, void*), va_arg(args, void*));
    va_end(args);

    LOGD("ptrace request: %d, result: %ld\n", __request, result);

    if (result == -1 && errno) {
        perror("ptrace");
        exit(-1);
    }
    return result;
}

void ptrace_read(int pid, long address, uint8_t *buffer, size_t size) {
    size_t i;
    unsigned long word;
    size_t POINTER_SIZE = sizeof(unsigned long);
    size_t remaining = size % POINTER_SIZE;
    for (i = 0; i < size / POINTER_SIZE; ++i) {
        word = xptrace(PTRACE_PEEKDATA, pid, (void *) (address + i * POINTER_SIZE), NULL);
        memcpy(buffer + i * POINTER_SIZE, &word, POINTER_SIZE);
    }

    unsigned char *p = buffer + (size / POINTER_SIZE) * POINTER_SIZE;
    for (i = 0; i < remaining; ++i) {
        word = xptrace(PTRACE_PEEKDATA, pid, (void *) (address + (size / POINTER_SIZE) * POINTER_SIZE + i), NULL);
        auto *byte = (unsigned char *) &word;
        *p++ = *byte;
    }

}

void ptrace_write(pid_t pid, long address, void *data, size_t size) {
    size_t i;
    unsigned long word;
    size_t POINTER_SIZE = sizeof(unsigned long);
    size_t remaining = size % POINTER_SIZE;
    for (i = 0; i < size / POINTER_SIZE; ++i) {
        word = *((unsigned long *) ((unsigned char *) data + i * POINTER_SIZE));
        xptrace(PTRACE_POKEDATA, pid, (void *) (address + i * POINTER_SIZE), (void *) word);
    }

    unsigned char *p = (unsigned char *) data + (size / POINTER_SIZE) * POINTER_SIZE;
    for (i = 0; i < remaining; ++i) {
        word = xptrace(PTRACE_PEEKDATA, pid,
                       (void *) (address + (size / POINTER_SIZE) * POINTER_SIZE + i), NULL);
        auto *byte = (unsigned char *) &word;
        *byte = *p++;
        xptrace(PTRACE_POKEDATA, pid, (void *) (address + (size / POINTER_SIZE) * POINTER_SIZE + i),
                (void *) word);
    }
}

template<typename Ret>
Ret call_remote_call(int pid, long address, int argc, long *args) {
    pt_regs backup_regs{}, regs{};
    iovec regs_iov{
            .iov_base = (void *) &regs,
            .iov_len = sizeof(pt_regs)
    };
    iovec backup_iov = {
            .iov_base = (void *) &backup_regs,
            .iov_len = sizeof(pt_regs)
    };

    xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regs_iov);
    memcpy(&backup_regs, &regs, sizeof(pt_regs));

    for (int i = 0; i < argc && i < REGS_ARG_NUM; ++i) {
        regs.uregs[i] = args[i];
    }

    if (argc > REGS_ARG_NUM) {
        regs.ARM_sp -= (argc - REGS_ARG_NUM) * sizeof(long);
        long *data = args + REGS_ARG_NUM;
        ptrace_write(pid, regs.ARM_sp, (uint8_t *) data, (argc - REGS_ARG_NUM) * sizeof(long));
    }

    regs.ARM_lr = 0;
    regs.ARM_pc = address;

#define CPSR_T_MASK (1u << 5)
    if (regs.ARM_pc & 1) {
        // thumb
        regs.ARM_pc &= (~1u);
        regs.ARM_cpsr |= CPSR_T_MASK;
    } else {
        // arm
        regs.ARM_cpsr &= ~CPSR_T_MASK;
    }
    xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &regs_iov);
    xptrace(PTRACE_CONT, pid, NULL, NULL);

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while ((stat & 0xFF) != 0x7f) {
        xptrace(PTRACE_CONT, pid);
        waitpid(pid, &stat, WUNTRACED);
    }

    xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regs_iov);
    xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &backup_iov);

    LOGD("call_remote_call pid: %d, address: %lx, argc: %d, args: %p, result: %lx, start: %lx, end: %lx",
         pid, address, argc, args, regs.uregs[0], address, regs.ARM_pc);

    if constexpr (std::is_void_v<Ret>) {
        return;
    } else {
        auto result = (Ret) (regs.uregs[0]);
        return result;
    }
}

template<typename Ret, typename... Args>
Ret call_remote_function(Ret (*func)(Args...), int pid, Args... args) {
    long remote_addr = get_remote_addr(pid, (void *) func);
    long params[sizeof...(Args)];
    int index = 0;
    ((params[index++] = (long) args), ...);
    return Ret(call_remote_call<Ret>(pid, remote_addr, sizeof(params) / sizeof(long), params));
}

void *alloc_str(int pid, const char *str) {
    void *address = call_remote_function<void *, size_t>(malloc, pid, strlen(str) + 1);
    ptrace_write(pid, (long) address, (void *) str, strlen(str) + 1);
    return address;
}

struct map_info {
    long start;
    long end;
    uint8_t perms;
};

void hide_module(pid_t pid, const char *module_name) {
    char file_name[50];
    if (pid == -1) {
        snprintf(file_name, 50, "/proc/self/maps");
    } else {
        snprintf(file_name, 50, "/proc/%d/maps", pid);
    }
    FILE *fp = fopen(file_name, "r");
    if (fp == nullptr) {
        return;
    }
    std::vector<map_info> result;
    char line[512];
    while (fgets(line, 512, fp) != nullptr) {
        if (strstr(line, module_name)) {
            map_info info{};
            char *p = strtok(line, "-");
            info.start = strtoul(p, nullptr, 16);
            p = strtok(nullptr, " ");
            info.end = strtoul(p, nullptr, 16);
            p = strtok(nullptr, " ");
            if (strchr(p, 'r')) info.perms |= PROT_READ;
            if (strchr(p, 'w')) info.perms |= PROT_WRITE;
            if (strchr(p, 'x')) info.perms |= PROT_EXEC;
            if (strchr(p, 'r')) info.perms |= PROT_READ;

            result.push_back(info);
        }
    }

    for (const auto &info: result) {
        long address = info.start;
        long size = info.end - address;

        LOGI("Hiding memory: %lx - %lx", address, info.end);

        void *map = call_remote_function<void *, void *, size_t, int, int, int, long>(mmap, pid,
                                                                                      0,
                                                                                      size,
                                                                                      PROT_WRITE | PROT_READ,
                                                                                      MAP_ANONYMOUS | MAP_PRIVATE, -1,
                                                                                      0);
        if (map == nullptr) {
            LOGE("Failed to allocate memory");
            return;
        }

        if ((info.perms & PROT_READ) == 0) {
            LOGI("Removing memory protection: %s", module_name);
            call_remote_function<int, void *, size_t, int>(mprotect, pid, (void *) address, size, PROT_READ);
        }

        call_remote_function<void *, void *, const void *, size_t>(memcpy, pid, map, (void *) address,
                                                                   (size_t) size);
        long elf_magic = 0;
        ptrace_read(pid, (long) address, (uint8_t *) &elf_magic, 4);

        if (elf_magic == 0x464c457f) {
            LOGI("ELF Magic Found: %s, address: %lx, Magic: %lx", module_name, address, elf_magic);
            LOGI("Clearing ELF Header: %s", module_name);

#if defined(__aarch64__)
            call_remote_function<void *, void *, int, size_t>(memset, pid, (void *) map, 0, sizeof(Elf64_Ehdr));
#else
            call_remote_function<void *, void *, int, size_t>(memset, pid, (void *) map, 0, sizeof(Elf32_Ehdr));
#endif
        }

        long addr = get_remote_addr(pid, (void *) mremap);

        long params[] = {(long) map, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, (long) address};
        call_remote_call<void>(pid, addr, sizeof(params) / sizeof(size_t), params);

        call_remote_function<int, void *, size_t, int>(mprotect, pid, (void *) address, size, info.perms);
    }

    fclose(fp);
}

void run_server(std::promise<int> &promiseObj) {
    int sockfd = 0, newsockfd = 0;
    socklen_t client_len;
    struct sockaddr_in server_addr{}, client_addr{};
    ssize_t totalBytesReceived = 0;

    struct pack {
        size_t length;
        char *data;
    } pack{};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct timeval timeout{};
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));

    if (HANDLE_EINTR(bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
        perror("bind");
        goto err;
    }

    if (HANDLE_EINTR(listen(sockfd, 1)) < 0) {
        perror("listen");
        goto err;
    }

    client_len = sizeof(client_addr);
    newsockfd = HANDLE_EINTR(accept(sockfd, (struct sockaddr *) &client_addr, &client_len));
    if (newsockfd < 0) {
        perror("accept");
        goto err;
    }

    if (HANDLE_EINTR(recv(newsockfd, &pack.length, sizeof(pack.length), 0)) < 0) {
        perror("recv");
        goto err;
    }

    pack.data = new char[pack.length];

    while (true) {
        ssize_t numBytesReceived = HANDLE_EINTR(
                recv(newsockfd, pack.data + totalBytesReceived, pack.length - totalBytesReceived, 0));
        if (numBytesReceived > 0) {
            totalBytesReceived += numBytesReceived;
        } else if (totalBytesReceived >= pack.length) {
            nlohmann::json j = nlohmann::json::parse(pack.data);
            LOGI("Received: %s", j.dump().c_str());
            promiseObj.set_value(j["pid"]);
            break;
        } else {
            perror("recv failed");
            goto err;
        }

    }

    clear:
    close(newsockfd);
    close(sockfd);
    delete pack.data;
    return;

    err:
    promiseObj.set_value(-1);
    goto clear;
}

void inject_module() {
    kill(g_pid, SIGCONT);
    xptrace(PTRACE_ATTACH, g_pid, NULL, NULL);
    waitpid(g_pid, nullptr, WUNTRACED);

    std::string temp_buffer;
    auto path = g_so_path;
    if (g_spawn) {
        char currentPath[FILENAME_MAX];
        if (getcwd(currentPath, sizeof(currentPath)) != nullptr) {
            temp_buffer = std::string(currentPath) + "/libtcore.so";
            path = temp_buffer.c_str();
        }

        long addr = get_remote_addr(g_pid, (void *) fork);
        uint8_t bytes[8] = {0};
        ptrace_read(g_pid, addr, bytes, 8);
        LOGD("fork: %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
             bytes[5],
             bytes[6], bytes[7]);
        //50 00 00 58 00 02 1f d6
        if (bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x58 &&
            bytes[4] == 0x00 && bytes[5] == 0x02 && bytes[6] == 0x1f && bytes[7] == 0xd6) {
            LOGE("Inject failed. Please disable frida server or another hook tool.");
            return;
        }
    }

    void *address = alloc_str(g_pid, path);
    LOGI("Injecting %s into %d", path, g_pid);

    auto handle = call_remote_function<void *, const char *, int>(dlopen, g_pid, (const char *) address,
                                                                  RTLD_NOW | RTLD_GLOBAL);

    call_remote_function<void, void *>(free, g_pid, address);

    if (g_hide) hide_module(g_pid, path);

    if (handle) {
        if (g_spawn) {
            void *sym_name = alloc_str(g_pid, "ainject");
            auto fun = (void (*)(void *, void *)) call_remote_function<void *, void *, const char *>(dlsym, g_pid,
                                                                                                     handle,
                                                                                                     (const char *) sym_name);

            if (fun) {
                LOGI("Injecting...");
                void *remote_pkg = alloc_str(g_pid, g_package_name);
                void *remote_so = alloc_str(g_pid, g_so_path);

                long params[] = {(long) remote_pkg, (long) remote_so};
                call_remote_call<void>(g_pid, (long) fun, 2, (long *) &params);

                call_remote_function<void, void *>(free, g_pid, remote_pkg);
                call_remote_function<void, void *>(free, g_pid, remote_so);
            } else {
                LOGE("not found ainject");
            }

            call_remote_function<void, void *>(free, g_pid, sym_name);



            if (g_hide_beta) {
                void *sym_name1 = alloc_str(g_pid, "enable_hide");
                auto fun1 = (void (*)(void *, void *)) call_remote_function<void *, void *, const char *>(dlsym, g_pid,
                                                                                                          handle,
                                                                                                          (const char *) sym_name1);

                if (fun1) {
                    call_remote_call<void>(g_pid, (long) fun1, 0, nullptr);
                }
                call_remote_function<void, void *>(free, g_pid, sym_name1);
            }

        }
        if (!g_spawn) {
            LOGI("Inject success.");
        }
    } else {
        char *error = call_remote_function<char *>(dlerror, g_pid);
        char buffer[256];
        ptrace_read(g_pid, (long) error, (uint8_t *) buffer, 256);
        LOGE("Inject failed. %s", buffer);
        return;
    }

    xptrace(PTRACE_DETACH, g_pid, NULL, NULL);
    if (g_spawn) {
        std::promise<int> promiseObj;
        std::thread serv(run_server, std::ref(promiseObj));
        system(std::string("am force-stop ").append(g_package_name).c_str());
        system(std::string("am start -D $(cmd package resolve-activity --brief '").append(g_package_name).append(
                "'| tail -n 1)").c_str());
        serv.join();
        LOGD("Waiting for client connection...");
        int child_pid = promiseObj.get_future().get();
        if (child_pid > 0) {
            if (g_hide) {
                xptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
                LOGI("Hiding app module...");
                hide_module(child_pid, g_so_path);
                xptrace(PTRACE_DETACH, child_pid, NULL, NULL);
            }

            LOGI("Inject success.");
        } else if (child_pid == -1) {
            LOGE("Inject failed. Failed to connect to client.");
        }



        // 释放资源
        kill(g_pid, SIGCONT);
        xptrace(PTRACE_ATTACH, g_pid, NULL, NULL);
        void *sym_name = alloc_str(g_pid, "unload");
        auto fun = (void (*)(void *, void *)) call_remote_function<void *, void *, const char *>(dlsym, g_pid,
                                                                                                 handle,
                                                                                                 (const char *) sym_name);
        if (fun) {
            call_remote_call<void>(g_pid, (long) fun, 0, nullptr);
        }
        call_remote_function<void, void *>(free, g_pid, sym_name);
        call_remote_function<int, void *>(dlclose, g_pid, handle);
        xptrace(PTRACE_DETACH, g_pid, NULL, NULL);
    }

}

void show_help(const char *name) {
    LOGI("Usage: %s --hide -f -p <package name>  <so path>", name);
    LOGI("Options:");
    LOGI("  -p <package name> <so path>  Inject so to the specified package.");
    LOGI("  -P <pid> <so path>           Inject so to the specified pid.");
    LOGI("  --hide                       Hide the injected module.");
    LOGI("  --hide1                      Hide the injected module. (soinfo)");
    LOGI("  -h                           Show this help.");
    LOGI("  -f                           Spwan a new process and inject to it. only for android app.");
}

int main(int argc, const char *argv[]) {
    if (argc < 4) {
        show_help(argv[0]);
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0) {
            g_package_name = argv[++i];
            g_so_path = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0) {
            g_pid = atoi(argv[++i]);
            g_so_path = argv[++i];
        } else if (strcmp(argv[i], "--hide") == 0) {
            g_hide = true;
        } else if (strcmp(argv[i], "--hide1") == 0) {
            g_hide_beta = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            show_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-f") == 0) {
            g_spawn = true;
        }
    }
    if (g_spawn) {
#if defined(__aarch64__)
        g_pid = get_pid("zygote64");
#else
        g_pid = get_pid("zygote");
#endif
        if (g_pid == -1) {
            LOGE("zygote process not found.");
            return -1;
        }
    } else {
        g_pid = get_pid(g_package_name);
        if (g_pid == -1) {
            LOGE("process not found.");
            return -1;
        }
    }

    if (g_spawn && g_package_name == nullptr) {
        LOGE("package name is required when using -f option.");
        return -1;
    }

    if (g_spawn) {
        char v[128] = {0};
        __system_property_get("persist.sys.usap_pool_enabled", v);
        LOGI("usap pool enabled: %s", v);
        if (strcmp(v, "true") == 0) {
            LOGE("unsupported usap pool enabled. Please disable it.");
            LOGE(" setprop persist.sys.usap_pool_enabled false & reboot");
            return -1;
        }
    }

    LOGD("package name: %s, so path: %s, pid: %d, hide: %d spawn:%d", g_package_name, g_so_path, g_pid, g_hide,
         g_spawn);


    setenforce(false);
    inject_module();
    setenforce(true);
    return 0;
}