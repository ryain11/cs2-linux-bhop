#pragma once

#include <sstream>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <optional>
#include <fstream>
#include <pthread.h>
#include <unistd.h>
#include "Sig.hpp"

struct ModuleInfo {
    uintptr_t base = 0;
    size_t size = 0;
};

struct FindModuleCtx {
    const char* target_name;
    ModuleInfo result;
    bool found = false;
};

static int phdr_callback(struct dl_phdr_info* info, size_t, void* data) {
    auto* ctx = static_cast<FindModuleCtx*>(data);

    // info->dlpi_name is empty for the main executable
    const char* name = info->dlpi_name;
    if (!name || !*name) return 0;

    if (std::strstr(name, ctx->target_name) == nullptr) return 0;

    uintptr_t base = info->dlpi_addr;
    uintptr_t min_addr = UINTPTR_MAX;
    uintptr_t max_addr = 0;

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD) continue; // only loadable segments count
        uintptr_t seg_start = base + phdr.p_vaddr;
        uintptr_t seg_end = seg_start + phdr.p_memsz;
        if (seg_start < min_addr) min_addr = seg_start;
        if (seg_end > max_addr) max_addr = seg_end;
    }

    if (max_addr > min_addr) {
        ctx->result.base = min_addr;
        ctx->result.size = max_addr - min_addr;
        ctx->found = true;
        return 1; // stop iterating, found it
    }
    return 0;
}

std::optional<ModuleInfo> get_module_info(const std::string& module_name) {
    FindModuleCtx ctx{module_name.c_str(), {}, false};
    dl_iterate_phdr(phdr_callback, &ctx);
    if (!ctx.found) return std::nullopt;
    return ctx.result;
}

uintptr_t FindPatternInModule(const char* module_name, const char* pattern) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return 0;

    std::string line;
    while (std::getline(maps, line)) {
        // Target readable segments of the module
        if (line.find(module_name) != std::string::npos && line.find(" r") != std::string::npos) {
            std::istringstream iss(line);
            std::string address_range;
            iss >> address_range;

            size_t dash = address_range.find('-');
            if (dash == std::string::npos) continue;

            uintptr_t start = std::strtoull(address_range.substr(0, dash).c_str(), nullptr, 16);
            uintptr_t end   = std::strtoull(address_range.substr(dash + 1).c_str(), nullptr, 16);
            size_t size     = end - start;

            const void* match = Sig::find(reinterpret_cast<const void*>(start), size, pattern);
            if (match) {
                return reinterpret_cast<uintptr_t>(match);
            }
        }
    }
    return 0;
}