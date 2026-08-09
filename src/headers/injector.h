#include <fstream>
#include <iostream>
#include <cstdint>
#include <string>
#include <dlfcn.h>

#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dirent.h>

std::string getLibraryDirectory()
{
    Dl_info info{};

    if (dladdr(reinterpret_cast<void*>(&getLibraryDirectory), &info) == 0)
        return {};

    if (!info.dli_fname)
        return {};

    char resolved[PATH_MAX];

    if (realpath(info.dli_fname, resolved) == nullptr)
        return {};

    std::string path = resolved;

    const auto pos = path.find_last_of('/');

    if (pos == std::string::npos)
        return {};

    return path.substr(0, pos);
}

pid_t findProcessByName(const std::string& name)
{
    DIR* dir = opendir("/proc");
    if (!dir)
        return -1;

    dirent* entry;

    while ((entry = readdir(dir)) != nullptr)
    {
        if (entry->d_type != DT_DIR)
            continue;

        char* end = nullptr;
        long pid = std::strtol(entry->d_name, &end, 10);

        if (*end != '\0' || pid <= 0)
            continue;

        std::ifstream comm(
            std::string("/proc/") + entry->d_name + "/comm"
        );

        std::string processName;
        if (std::getline(comm, processName) && processName == name)
        {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }
    }

    closedir(dir);
    return -1;
}

// 1. Module base address calculation
uintptr_t get_module_base(pid_t pid, const std::string& module_name) {
    std::string pid_str = (pid == 0) ? "self" : std::to_string(pid);
    std::ifstream maps("/proc/" + pid_str + "/maps");
    std::string line;

    while (std::getline(maps, line)) {
        if (line.find(module_name) != std::string::npos) {
            uintptr_t base = 0;
            if (sscanf(line.c_str(), "%lx-", &base) == 1) {
                return base;
            }
        }
    }
    return 0;
}

uintptr_t call_remote_function(pid_t pid, uintptr_t func_addr, 
                               uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, 
                               uintptr_t arg4, uintptr_t arg5, uintptr_t arg6) {
    struct user_regs_struct orig_regs, regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        perror("[-] PTRACE_GETREGS failed");
        return 0;
    }
    regs = orig_regs;

    // 1. Clear Red Zone and Align Stack
    regs.rsp -= 128;
    regs.rsp &= ~0xfUL;

    // 2. Push dummy return address (0x0) onto stack
    regs.rsp -= 8;
    long dummy_ret = 0;
    ptrace(PTRACE_POKETEXT, pid, (void*)regs.rsp, (void*)dummy_ret);

    // 3. CRITICAL: Reset orig_rax to -1 to prevent Linux from restarting an interrupted syscall!
    regs.orig_rax = -1;

    // 4. Set C ABI Function Arguments (System V AMD64)
    regs.rdi = arg1; // 1st Arg
    regs.rsi = arg2; // 2nd Arg
    regs.rdx = arg3; // 3rd Arg
    regs.rcx = arg4; // 4th Arg
    regs.r8  = arg5; // 5th Arg
    regs.r9  = arg6; // 6th Arg
    regs.rip = func_addr;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("[-] PTRACE_SETREGS failed");
        return 0;
    }

    // 5. Resume process and wait for SIGSEGV trap
    int status = 0;
    int signal_to_send = 0;

    while (true) {
        if (ptrace(PTRACE_CONT, pid, NULL, (void*)(uintptr_t)signal_to_send) == -1) {
            perror("[-] PTRACE_CONT failed");
            break;
        }

        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            
            if (sig == SIGSEGV) {
                break; // Target hit the dummy 0x0 return address!
            }
            
            // Forward any other signal (e.g. SIGALRM, SIGCHLD) and continue execution
            signal_to_send = sig;
        } else {
            std::cerr << "[-] Target process exited or crashed during function call\n";
            return 0;
        }
    }

    // 6. Read returned RAX value
    struct user_regs_struct result_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &result_regs);
    uintptr_t return_val = result_regs.rax;

    // 7. Restore original register state
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);

    return return_val;
}

uintptr_t get_remote_mmap_address(pid_t target_pid) {
    std::string lib_name = "libc.so";

    uintptr_t local_base  = get_module_base(0, lib_name);
    uintptr_t remote_base = get_module_base(target_pid, lib_name);

    if (!local_base || !remote_base) {
        std::cerr << "[-] Failed to locate " << lib_name << " base address\n";
        return 0;
    }

    void* local_mmap = dlsym(RTLD_DEFAULT, "mmap");
    if (!local_mmap) {
        std::cerr << "[-] Failed to resolve local mmap address\n";
        return 0;
    }

    uintptr_t offset = reinterpret_cast<uintptr_t>(local_mmap) - local_base;
    return remote_base + offset;
}

// 2. Find remote syscall instruction (0x0f 0x05)
uintptr_t find_remote_syscall(pid_t pid) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    uintptr_t start = 0, end = 0;

    while (std::getline(maps, line)) {
        if (line.find("r-xp") != std::string::npos || line.find("r--p") != std::string::npos) {
            if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                for (uintptr_t addr = start; addr < end - 2; addr += sizeof(long)) {
                    long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
                    unsigned char* bytes = reinterpret_cast<unsigned char*>(&data);
                    for (size_t i = 0; i < sizeof(long) - 1; ++i) {
                        if (bytes[i] == 0x0f && bytes[i + 1] == 0x05) {
                            return addr + i;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// 3. Resolve remote dlopen address
uintptr_t get_remote_dlopen_address(pid_t target_pid) {
    std::string lib_name = "libc.so";

    uintptr_t local_base  = get_module_base(0, lib_name);
    uintptr_t remote_base = get_module_base(target_pid, lib_name);

    if (!local_base || !remote_base) {
        lib_name = "libdl.so";
        local_base  = get_module_base(0, lib_name);
        remote_base = get_module_base(target_pid, lib_name);
    }

    if (!local_base || !remote_base) {
        std::cerr << "[-] Failed to locate " << lib_name << " base address\n";
        return 0;
    }

    void* local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        local_dlopen = dlsym(RTLD_DEFAULT, "__libc_dlopen_mode");
    }

    if (!local_dlopen) {
        std::cerr << "[-] Failed to resolve local dlopen address\n";
        return 0;
    }

    uintptr_t offset = reinterpret_cast<uintptr_t>(local_dlopen) - local_base;
    return remote_base + offset;
}

// 4. Allocate memory using remote mmap (Assumes process is already attached/stopped)
uintptr_t allocate_remote_memory(pid_t pid, uintptr_t mmap_addr, size_t size) {
    // mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    uintptr_t addr = call_remote_function(
        pid, mmap_addr,
        0,                                   // addr = NULL
        size,                                // length
        PROT_READ | PROT_WRITE,              // prot
        MAP_PRIVATE | MAP_ANONYMOUS,         // flags
        (uintptr_t)-1,                       // fd = -1
        0                                    // offset = 0
    );

    if (addr > (uintptr_t)-4095 || addr == 0) {
        std::cerr << "[-] mmap failed with return code: 0x" << std::hex << addr << std::dec << "\n";
        return 0;
    }

    return addr;
}

// 5. Write data into target process memory space
bool write_to_remote_memory(pid_t pid, uintptr_t remote_addr, const void* src_buffer, size_t size) {
    struct iovec local_iov  = { .iov_base = const_cast<void*>(src_buffer), .iov_len = size };
    struct iovec remote_iov = { .iov_base = reinterpret_cast<void*>(remote_addr), .iov_len = size };

    ssize_t bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    return (bytes_written == static_cast<ssize_t>(size));
}

// 6. Execute dlopen (Assumes process is already attached/stopped)
uintptr_t execute_remote_dlopen(pid_t pid, uintptr_t dlopen_addr, uintptr_t str_addr) {
    // dlopen(str_addr, RTLD_NOW)
    return call_remote_function(
        pid, dlopen_addr,
        str_addr, // Arg 1: path string address
        RTLD_NOW, // Arg 2: flags
        0, 0, 0, 0
    );
}