//
// Created by Mrack on 2024/4/19.
//
#include "utils.h"
#include "elfio/elfio.hpp"


JavaVM *gVm = nullptr;

const char *get_data_path(jobject context) {
    JavaEnv env;
    if (env.isNull()) {
        return nullptr;
    }
    jclass context_class = env->GetObjectClass(context);
    jmethodID getFilesDir = env->GetMethodID(context_class, "getDataDir", "()Ljava/io/File;");
    jobject file = env->CallObjectMethod(context, getFilesDir);
    jclass file_class = env->GetObjectClass(file);
    jmethodID getPath = env->GetMethodID(file_class, "getPath", "()Ljava/lang/String;");
    jstring path = (jstring) env->CallObjectMethod(file, getPath);
    const char *data = env->GetStringUTFChars(path, 0);
    return data;
}

int get_sdk_level() {
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    char sdk[128] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}


char *get_linker_path() {
    char *linker;
#if defined(__aarch64__)
    if (get_sdk_level() >= ANDROID_R) {
        linker = (char *) "/apex/com.android.runtime/bin/linker64";
    } else if (get_sdk_level() >= ANDROID_Q) {
        linker = (char *) "/apex/com.android.runtime/bin/linker64";
    } else {
        linker = (char *) "/system/bin/linker64";
    }
#else
    if (get_sdk_level() >= ANDROID_R) {
        linker = (char *) "/apex/com.android.runtime/bin/linker";
    } else if (get_sdk_level() >= ANDROID_Q) {
        linker = (char *) "/apex/com.android.runtime/bin/linker";
    } else {
        linker = (char *) "/system/bin/linker";
    }
#endif
    return linker;
}

const char *find_path_from_maps(const char *soname) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return nullptr;
    }
    // get path from maps
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, soname)) {
            char *start = strchr(line, '/');
            char *path = strdup(start);
            path[strlen(path) - 1] = '\0';
            fclose(fp);
            return path;
        }
    }
    fclose(fp);
    return nullptr;
}

std::pair<size_t, size_t> find_info_from_maps(const char *soname) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return std::make_pair(0, 0);
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, soname)) {
            char *start = strtok(line, "-");
            char *end = strtok(NULL, " ");
            fclose(fp);
            return std::make_pair((size_t) strtoul(start, NULL, 16),
                                  strtoul(end, NULL, 16) - strtoul(start, NULL, 16));
        }
    }
    fclose(fp);
    return std::make_pair(0, 0);
}

u_char *hex2char(const char *hex) {
    size_t len = strlen(hex);
    u_char *result = (u_char *) malloc(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        if (hex[i] == '?' || hex[i + 1] == '?') {
            result[i / 2] = 0xcc;
            continue;
        }
        sscanf(hex + i, "%2hhx", &result[i / 2]);
    }
    return result;
}

int search_hex(u_char *haystack, size_t haystackLen, const char *needle) {
    size_t needleLen = strlen(needle) / 2;
    u_char *needleChar = hex2char(needle);
    int result = boyer_moore_search(haystack, haystackLen, needleChar, needleLen);
    free(needleChar);
    return result;
}

int boyer_moore_search(u_char *haystack, size_t haystackLen, u_char *needle, size_t needleLen) {
    size_t skipTable[256];
    for (size_t i = 0; i < 256; i++) {
        skipTable[i] = needleLen;
    }
    for (size_t i = 0; i < needleLen - 1; i++) {
        skipTable[(size_t) needle[i]] = needleLen - 1 - i;
    }
    size_t i = 0;
    while (i <= haystackLen - needleLen) {
        int j = needleLen - 1;
        while (j >= 0 && (haystack[i + j] == needle[j] || needle[j] == 0xcc)) {
            j--;
        }
        if (j < 0) {
            return i;
        } else {
            i += skipTable[(size_t) haystack[i + needleLen - 1]];
        }
    }
    return -1;
}


void *get_address_from_module(const char *module_path, const char *symbol_name) {
    ELFIO::elfio elffile;
    std::string name;
    ELFIO::Elf64_Addr value;
    ELFIO::Elf_Xword size;
    unsigned char bind;
    unsigned char type;
    ELFIO::Elf_Half section_index;
    unsigned char other;
    const char *file_name = strrchr(module_path, '/');
    elffile.load(module_path);
    size_t module_base = find_info_from_maps(file_name).first;
    ELFIO::section *s = elffile.sections[".dynsym"];
    size_t offset = 0;
    if (s != nullptr) {
        ELFIO::symbol_section_accessor symbol_accessor(elffile, s);
        for (int i = 0; i < symbol_accessor.get_symbols_num(); ++i) {
            symbol_accessor.get_symbol(i, name, value, size, bind, type, section_index, other);
            if (name.find(symbol_name) != std::string::npos && type == ELFIO::STT_FUNC) {
                offset = value;
                break;
            }
        }
    }

    s = elffile.sections[".symtab"];
    if (s != nullptr) {
        ELFIO::symbol_section_accessor symbol_accessor(elffile, s);
        for (int i = 0; i < symbol_accessor.get_symbols_num(); ++i) {
            symbol_accessor.get_symbol(i, name, value, size, bind, type, section_index, other);
            if (name.find(symbol_name) != std::string::npos) {
                offset = value;
                break;
            }
        }
    }

    for (const auto &segment: elffile.segments) {
        if (offset >= segment->get_offset() &&
            offset <= segment->get_offset() + segment->get_file_size()) {
            return (void *) (module_base + offset - (segment->get_virtual_address() - segment->get_offset()));
        }
    }
    return nullptr;
}