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
    
    // Si Darwin 26 rejette l'architecture (EBADARCH=86 / ENOEXEC=8), on force le succès
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
static const char *bootArgBeta[] = { "-fx86beta" };

// Structure de configuration Lilu valide
PluginConfiguration ADDPR(config) {
    PluginConfiguration::STRING_MID(ADDPR(configName)),
    25, // KernelVersion min (Darwin 25 / macOS 26)
    27, // KernelVersion max (Darwin 27 / macOS 28)
    PluginConfiguration::SMP_PRODUCT_ALL,
    bootArgOff, arrsize(bootArgOff),
    bootArgDebug, arrsize(bootArgDebug),
    bootArgBeta, arrsize(bootArgBeta),
    26, // KernelVersion pour deboguage
    []() {
        fx86.init();
    }
};

bool FX86::init() {
    SYSLOG("FX86", "Initialisation du kext ForceX86Exec");

    // Enregistrement sur le chargement du noyau via l'API Lilu
    LiluAPI::Error error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher, mach_vm_address_t address, size_t size) {
        static_cast<FX86 *>(user)->processKernel(user, patcher, address, size);
    }, this);

    if (error != LiluAPI::Error::NoError) {
        SYSLOG("FX86", "Échec d'enregistrement Lilu: %d", error);
        return false;
    }

    return true;
}

void FX86::processKernel(void *user, KernelPatcher &patcher, mach_vm_address_t address, size_t size) {
    // Résolution des symboles et application des hooks noyau
    mach_vm_address_t addr_execve = patcher.solveSymbol(KernelPatcher::KernelID, "_mac_execve");
    if (addr_execve) {
        org_mac_execve = reinterpret_cast<mac_execve_t>(patcher.routeMultiple(KernelPatcher::KernelID, addr_execve, reinterpret_cast<mach_vm_address_t>(my_mac_execve)));
        DBGLOG("FX86", "Hook _mac_execve actif");
    }

    mach_vm_address_t addr_cs = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_page");
    if (addr_cs) {
        org_cs_validate_page = reinterpret_cast<cs_validate_page_t>(patcher.routeMultiple(KernelPatcher::KernelID, addr_cs, reinterpret_cast<mach_vm_address_t>(my_cs_validate_page)));
        DBGLOG("FX86", "Hook _cs_validate_page actif");
    }
}

void FX86::deinit() {
}
