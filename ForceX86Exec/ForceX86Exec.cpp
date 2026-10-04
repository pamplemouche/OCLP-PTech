#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_patcher.hpp>

#include "ForceX86Exec.hpp"

static FX86 fx86;

typedef int (*mac_execve_t)(void *proc, void *uap, int32_t *retval, void *vp, uint32_t flags);
static mach_vm_address_t org_mac_execve = 0;

typedef void (*cs_validate_page_t)(void *vp, void *pager, uint64_t page_offset, const void *data, uint64_t *validated_len, boolean_t *validated, boolean_t *tainted);
static mach_vm_address_t org_cs_validate_page = 0;

static int my_mac_execve(void *proc, void *uap, int32_t *retval, void *vp, uint32_t flags) {
    int result = reinterpret_cast<mac_execve_t>(org_mac_execve)(proc, uap, retval, vp, flags);
    if (result == 86 || result == 8) {
        DBGLOG("FX86", "Bypass du controle d'architecture x86_64 sur mac_execve");
        return 0;
    }
    return result;
}

static void my_cs_validate_page(void *vp, void *pager, uint64_t page_offset, const void *data, uint64_t *validated_len, boolean_t *validated, boolean_t *tainted) {
    reinterpret_cast<cs_validate_page_t>(org_cs_validate_page)(vp, pager, page_offset, data, validated_len, validated, tainted);
    if (validated) *validated = TRUE;
    if (tainted) *tainted = FALSE;
}

static const char *bootArgOff[] = { "-fx86off" };
static const char *bootArgDebug[] = { "-fx86dbg" };
static const char *bootArgBeta[] = { "-fx86beta" };

// Structure PluginConfiguration Lilu (12 champs stricts)
PluginConfiguration ADDPR(config) {
    "ForceX86Exec",               // name
    1,                            // version
    LiluAPI::AllowNormal,         // disableFlags
    bootArgOff,                   // bootArgOff
    arrsize(bootArgOff),          // bootArgOffNum
    bootArgDebug,                 // bootArgDebug
    arrsize(bootArgDebug),        // bootArgDebugNum
    bootArgBeta,                  // bootArgBeta
    arrsize(bootArgBeta),         // bootArgBetaNum
    KernelVersion(0),             // minKernel (0 = aucune limite)
    KernelVersion(0),             // maxKernel (0 = aucune limite)
    0                             // pluginFlags
};

static void pluginStart() {
    fx86.init();
}

bool FX86::init() {
    SYSLOG("FX86", "Initialisation du kext ForceX86Exec");

    LiluAPI::Error error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher) {
        static_cast<FX86 *>(user)->processKernel(user, patcher);
    }, this);

    if (error != LiluAPI::Error::NoError) {
        SYSLOG("FX86", "Echec d'enregistrement Lilu : %d", error);
        return false;
    }

    return true;
}

void FX86::processKernel(void *user, KernelPatcher &patcher) {
    mach_vm_address_t addr_execve = patcher.solveSymbol(KernelPatcher::KernelID, "_mac_execve");
    if (addr_execve) {
        KernelPatcher::RouteRequest request("_mac_execve", my_mac_execve, org_mac_execve);
        if (patcher.routeMultiple(KernelPatcher::KernelID, &request, 1)) {
            DBGLOG("FX86", "Hook _mac_execve actif");
        }
    }

    mach_vm_address_t addr_cs = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_page");
    if (addr_cs) {
        KernelPatcher::RouteRequest request("_cs_validate_page", my_cs_validate_page, org_cs_validate_page);
        if (patcher.routeMultiple(KernelPatcher::KernelID, &request, 1)) {
            DBGLOG("FX86", "Hook _cs_validate_page actif");
        }
    }
}

void FX86::deinit() {
}
