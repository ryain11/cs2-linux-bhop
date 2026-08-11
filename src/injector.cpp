#include <cstring>
#include "headers/injector.h"

int main(int argc, char *argv[]) {

    pid_t pid = findProcessByName("cs2");

    if (pid == -1) {
        std::cerr << "[-] Process not found. Open cs2 before injecting\n";
        return 1;
    }

    // Step 1: Resolve remote addresses before attaching
    uintptr_t mmap_addr = get_remote_mmap_address(pid);
    uintptr_t dlopen_addr = get_remote_dlopen_address(pid);

    if (!mmap_addr || !dlopen_addr) {
        std::cerr << "[-] Failed to resolve remote function addresses\n";
        return 1;
    }

    std::cout << "[+] Found remote mmap at:   0x" << std::hex << mmap_addr << "\n";
    std::cout << "[+] Found remote dlopen at: 0x" << dlopen_addr << std::dec << "\n";

    // Step 2: Attach to target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("[-] ptrace PTRACE_ATTACH failed");
        return 1;
    }
    waitpid(pid, NULL, 0);

    std::string path = getLibraryDirectory() + "/cs2_bhop.so";
    const char* path_cstr = path.c_str();

    size_t path_len = strlen(path_cstr) + 1;
    uintptr_t allocated_mem = allocate_remote_memory(pid, mmap_addr, path_len);
    if (!allocated_mem) {
        std::cerr << "[-] Remote memory allocation failed\n";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    std::cout << "[+] Allocated remote buffer at: 0x" << std::hex << allocated_mem << std::dec << "\n";

    // Step 4: Write library path string into target memory space
    if (!write_to_remote_memory(pid, allocated_mem, path_cstr, path_len)) {
        std::cerr << "[-] Failed to write path string to remote memory.\nMake sure the .so is in the same directory with the injector\n";
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Step 5: Execute remote dlopen
    uintptr_t handle = execute_remote_dlopen(pid, dlopen_addr, allocated_mem);

    if (handle == 0) {
    std::cerr << "[-] FAILURE: dlopen returned NULL (0x0)\n";

    // Resolve remote dlerror address
    void* local_dlerror = dlsym(RTLD_DEFAULT, "dlerror");
    uintptr_t local_base = get_module_base(0, "libc.so");
    uintptr_t remote_base = get_module_base(pid, "libc.so");
    uintptr_t dlerror_addr = remote_base + (reinterpret_cast<uintptr_t>(local_dlerror) - local_base);

    // Call remote dlerror()
    uintptr_t err_str_ptr = call_remote_function(pid, dlerror_addr, 0, 0, 0, 0, 0, 0);

    if (err_str_ptr != 0) {
        char err_msg[256] = {0};
        struct iovec local_iov  = { .iov_base = err_msg, .iov_len = sizeof(err_msg) - 1 };
        struct iovec remote_iov = { .iov_base = reinterpret_cast<void*>(err_str_ptr), .iov_len = sizeof(err_msg) - 1 };
        process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
        std::cerr << "[-] Remote dlerror message: " << err_msg << "\n";
    }
    }

    // Step 6: Detach and restore process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return (handle != 0) ? 0 : 1;
}