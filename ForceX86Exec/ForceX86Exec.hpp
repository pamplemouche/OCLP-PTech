#ifndef ForceX86Exec_hpp
#define ForceX86Exec_hpp

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_patcher.hpp>

class FX86 {
public:
    bool init();
    void deinit();

private:
    void processKernel(void *user, KernelPatcher &patcher, mach_vm_address_t address, size_t size);
};

#endif /* ForceX86Exec_hpp */
