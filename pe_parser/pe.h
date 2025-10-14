#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PE_SUBSYSTEM_LIST(X)                   \
    X(IMAGE_SUBSYSTEM_UNKNOWN)                 \
    X(IMAGE_SUBSYSTEM_NATIVE)                  \
    X(IMAGE_SUBSYSTEM_WINDOWS_GUI)             \
    X(IMAGE_SUBSYSTEM_WINDOWS_CUI)             \
    X(IMAGE_SUBSYSTEM_OS2_CUI)                 \
    X(IMAGE_SUBSYSTEM_POSIX_CUI)               \
    X(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI)          \
    X(IMAGE_SUBSYSTEM_EFI_APPLICATION)         \
    X(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) \
    X(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER)      \
    X(IMAGE_SUBSYSTEM_EFI_ROM)                 \
    X(IMAGE_SUBSYSTEM_XBOX)                    \
    X(IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)

static inline const char *subsys_name(WORD v)
{
    switch (v) {
#define CASE(name) \
    case name:     \
        return #name;
        PE_SUBSYSTEM_LIST(CASE)
#undef CASE
    default:
        return "unknown value";
    }
}

#define PE_MACHINE_LIST(X)                                          \
    X(IMAGE_FILE_MACHINE_UNKNOWN, "Any machine type")               \
    X(IMAGE_FILE_MACHINE_TARGET_HOST, "Target host (non-WoW)")      \
    X(IMAGE_FILE_MACHINE_I386, "Intel 386+")                        \
    X(IMAGE_FILE_MACHINE_R3000, "MIPS R3000 LE (0x160=BE)")         \
    X(IMAGE_FILE_MACHINE_R4000, "MIPS R4000 LE")                    \
    X(IMAGE_FILE_MACHINE_R10000, "MIPS R10000 LE")                  \
    X(IMAGE_FILE_MACHINE_WCEMIPSV2, "MIPS WCE v2 LE")               \
    X(IMAGE_FILE_MACHINE_ALPHA, "Alpha AXP")                        \
    X(IMAGE_FILE_MACHINE_SH3, "Hitachi SH3 LE")                     \
    X(IMAGE_FILE_MACHINE_SH3DSP, "Hitachi SH3 DSP")                 \
    X(IMAGE_FILE_MACHINE_SH3E, "Hitachi SH3E LE")                   \
    X(IMAGE_FILE_MACHINE_SH4, "Hitachi SH4 LE")                     \
    X(IMAGE_FILE_MACHINE_SH5, "Hitachi SH5")                        \
    X(IMAGE_FILE_MACHINE_ARM, "ARM LE")                             \
    X(IMAGE_FILE_MACHINE_THUMB, "ARM Thumb/Thumb-2 LE")             \
    X(IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 LE")                   \
    X(IMAGE_FILE_MACHINE_AM33, "Matsushita AM33")                   \
    X(IMAGE_FILE_MACHINE_POWERPC, "IBM PowerPC LE")                 \
    X(IMAGE_FILE_MACHINE_POWERPCFP, "IBM PowerPC (FP)")             \
    X(IMAGE_FILE_MACHINE_IA64, "Intel Itanium (IA-64)")             \
    X(IMAGE_FILE_MACHINE_MIPS16, "MIPS16")                          \
    X(IMAGE_FILE_MACHINE_ALPHA64, "Alpha AXP 64") /* AXP64 alias */ \
    X(IMAGE_FILE_MACHINE_MIPSFPU, "MIPS + FPU")                     \
    X(IMAGE_FILE_MACHINE_MIPSFPU16, "MIPS16 + FPU")                 \
    X(IMAGE_FILE_MACHINE_TRICORE, "Infineon TriCore")               \
    X(IMAGE_FILE_MACHINE_CEF, "CEF")                                \
    X(IMAGE_FILE_MACHINE_EBC, "EFI Byte Code")                      \
    X(IMAGE_FILE_MACHINE_AMD64, "AMD64 (x64)")                      \
    X(IMAGE_FILE_MACHINE_M32R, "M32R LE")                           \
    X(IMAGE_FILE_MACHINE_ARM64, "ARM64 LE")                         \
    X(IMAGE_FILE_MACHINE_CEE, "CEE")

static inline const char *machine_name(WORD v)
{
    switch (v) {
#define CASE(N, D) \
    case N:        \
        return #N;
        PE_MACHINE_LIST(CASE)
#undef CASE
    default:
        return "unknown value";
    }
}

static inline const char *machine_desc(WORD v)
{
    switch (v) {
#define CASE(N, D) \
    case N:        \
        return D;
        PE_MACHINE_LIST(CASE)
#undef CASE
    default:
        return "Unknown machine";
    }
}

#ifdef __cplusplus
}
#endif
