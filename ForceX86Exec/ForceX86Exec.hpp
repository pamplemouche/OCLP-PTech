#ifndef ForceX86Exec_hpp
#define ForceX86Exec_hpp

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>

class FX86 {
public:
    bool init();
    void deinit();

private:
    void processKext(void *user, PluginConfiguration::Error error, mach_vm_address_t image, size_t size);
};

#endif /* ForceX86Exec_hpp */
