#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_patcher.hpp>

#include "ForceX86Exec.hpp"

static FX86 fx86;

typedef int (*mac_execve_t)(void *proc, void *uap, int32_t *retval, void *vp, uint32_t flags);
static mac_execve_t org_mac_execve = nullptr;

typedef void (*cs_validate_page_t)(void *vp, void *pager, uint64_t page_offset, const void *data, uint64_t *validated_len, boolean_t *validated, boolean_t *tainted);
static cs_validate_page_t org_cs_validate_page = nullptr;

// Interception de mac_execve pour autoriser les exécutables x86_64
static int my_mac_execve(void *proc, void *uap, int32_t *retval, void *vp, uint32_t flags) {
    int result = org_mac_execve(proc, uap, retval, vp, flags);
    
    // Si Darwin 26 rejette l'architecture (EBADARCH / ENOEXEC), on force le succès
    if (result == 86 || result == 8) {
        DBGLOG("FX86", "Bypass du contrôle d'architecture x86_64 sur mac_execve");
        return 0;
    }
    return result;
}

// Interception de cs_validate_page pour éviter le SIGKILL sur la signature
static void my_cs_validate_page(void *vp, void *pager, uint64_t page_offset, const void *data, uint64_t *validated_len, boolean_t *validated, boolean_t *tainted) {
    org_cs_validate_page(vp, pager, page_offset, data, validated_len, validated, tainted);
    
    if (validated) *validated = TRUE;
    if (tainted) *tainted = FALSE;
}

static const char *bootArgOff[] = { "-fx86off" };
static const char *bootArgDebug[] = { "-fx86dbg" };

PluginConfiguration ADDPR(config) {
    PluginConfiguration::PRODUCT_AUTODETECT,
    parseCustomBOOTARG(bootArgOff, arrsize(bootArgOff)),
    nullptr, 0,
    nullptr, 0,
    parseCustomBOOTARG(bootArgDebug, arrsize(bootArgDebug)),
    KernelVersion::GoldenGate,
    KernelVersion::GoldenGate,
    []() {
        fx86.init();
    }
};

bool FX86::init() {
    SYSLOG("FX86", "Initialisation du kext ForceX86Exec");

    LiluAPI::Error error = lilu.onKextLoad(nullptr, 0, [](void *user, PluginConfiguration::Error error, mach_vm_address_t image, size_t size) {
        static_cast<FX86 *>(user)->processKext(user, error, image, size);
    }, this);

    if (error != LiluAPI::Error::NoError) {
        SYSLOG("FX86", "Échec d'enregistrement Lilu: %d", error);
        return false;
    }

    return true;
}

void FX86::processKext(void *user, PluginConfiguration::Error error, mach_vm_address_t image, size_t size) {
    KernelPatcher &patcher = lilu.patcher;
    
    mach_vm_address_t addr_execve = patcher.solveSymbol(KernelPatcher::KernelID, "_mac_execve");
    if (addr_execve) {
        org_mac_execve = reinterpret_cast<mac_execve_t>(patcher.routeFunction(addr_execve, reinterpret_cast<mach_vm_address_t>(my_mac_execve)));
        DBGLOG("FX86", "Hook _mac_execve actif");
    }

    mach_vm_address_t addr_cs = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_page");
    if (addr_cs) {
        org_cs_validate_page = reinterpret_cast<cs_validate_page_t>(patcher.routeFunction(addr_cs, reinterpret_cast<mach_vm_address_t>(my_cs_validate_page)));
        DBGLOG("FX86", "Hook _cs_validate_page actif");
    }
}

void FX86::deinit() {
}
