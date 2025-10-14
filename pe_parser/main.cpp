#pragma warning(disable : 4996)

#include <Windows.h>
#include <iostream>

#include "color.h"
#include "debug.h"
#include "pe.h"

bool read_bin(const char filename[], char **buf, int *len)
{
    if (FILE *fp = fopen(filename, "rb")) {
        fseek(fp, 0, SEEK_END);
        *len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        *buf = (char *) malloc(*len);
        fread(*buf, sizeof(char), *len, fp);
        fclose(fp);

        return true;
    }
    return false;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        error("usage: %s <file>", argv[0]);
    }

    char *buf = nullptr;
    int buf_len = 0;

    info("reading executable");
    read_bin(argv[1], &buf, &buf_len);
    ok("buf @ 0x%p, len: 0x%x", buf, buf_len);

    BYTE *base = (BYTE *) buf;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *) buf;
    IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *) ((BYTE *) dos + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt32->Signature != IMAGE_NT_SIGNATURE) {
        error("are you sure this is a PE format file ?");
        exit(EXIT_FAILURE);
    }

    info("parsing headers");

    bool is64 = (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *) (base + dos->e_lfanew);

    info("PE header:");
    hexdump(dos, 0x40);

    info("NT header:");
    hexdump(nt64, 0x40);

    auto file_hdr = is64 ? nt64->FileHeader : nt32->FileHeader;
    BYTE *opt_hdr = is64 ? (BYTE *) &nt64->OptionalHeader : (BYTE *) &nt32->OptionalHeader;

    if (is64) {
        ok("machine: " ANSI_YELLOW "%s: %s" ANSI_RESET, machine_name(file_hdr.Machine), machine_desc(file_hdr.Machine));
        ok("image base: " ANSI_YELLOW "0x%llx" ANSI_RESET, nt64->OptionalHeader.ImageBase);
        ok("virtual size: " ANSI_YELLOW "0x%x" ANSI_RESET, nt64->OptionalHeader.SizeOfImage);
        ok("entry point: " ANSI_YELLOW "0x%x" ANSI_RESET, nt64->OptionalHeader.AddressOfEntryPoint);
        ok("sub system: " ANSI_YELLOW "%s" ANSI_RESET, subsys_name(nt64->OptionalHeader.Subsystem));
    } else {
        ok("machine: " ANSI_YELLOW "%s: %s" ANSI_RESET, machine_name(file_hdr.Machine), machine_desc(file_hdr.Machine));
        ok("image base: " ANSI_YELLOW "0x%x" ANSI_RESET, nt32->OptionalHeader.ImageBase);
        ok("virtual size: " ANSI_YELLOW "0x%x" ANSI_RESET, nt32->OptionalHeader.SizeOfImage);
        ok("entry point: " ANSI_YELLOW "0x%x" ANSI_RESET, nt32->OptionalHeader.AddressOfEntryPoint);
        ok("sub system: " ANSI_YELLOW "%s" ANSI_RESET, subsys_name(nt32->OptionalHeader.Subsystem));
    }

    info("parsing section headers");
    IMAGE_SECTION_HEADER *sec_hdrs = (IMAGE_SECTION_HEADER *) (opt_hdr + file_hdr.SizeOfOptionalHeader);
    void *section = base + sec_hdrs[0].PointerToRawData;

    ok("section headers:");
    for (int i = 0; i < file_hdr.NumberOfSections; i++) {
        printf("    " ANSI_GRAY "\\___" ANSI_RESET " [" ANSI_YELLOW "%8s" ANSI_RESET "] 0x%08x -> 0x%08x " ANSI_GRAY
               "(size: %d)\n" ANSI_RESET,
               sec_hdrs[i].Name, sec_hdrs[i].PointerToRawData, sec_hdrs[i].VirtualAddress, sec_hdrs[i].SizeOfRawData);
        section = base + sec_hdrs[i].PointerToRawData;
        // hexdump(section, 0x20);
    }

    auto rva_to_off = [&](DWORD rva) -> DWORD {
        for (int i = 0; i < file_hdr.NumberOfSections; ++i) {
            DWORD va = sec_hdrs[i].VirtualAddress;
            DWORD vsz = sec_hdrs[i].Misc.VirtualSize;
            DWORD rsz = sec_hdrs[i].SizeOfRawData;
            DWORD span = (vsz > rsz ? vsz : rsz);
            if (rva >= va && rva < va + span) {
                return sec_hdrs[i].PointerToRawData + (rva - va);
            }
        }
        return 0;
    };

    IMAGE_DATA_DIRECTORY *dirs = is64 ? &nt64->OptionalHeader.DataDirectory[0] : &nt32->OptionalHeader.DataDirectory[0];

    info("parsing export table");
    IMAGE_DATA_DIRECTORY *exp_dd = &dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exp_dd->VirtualAddress && exp_dd->Size >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
        IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *) (base + rva_to_off(exp_dd->VirtualAddress));

        DWORD *functions = (DWORD *) (base + rva_to_off(exp_dir->AddressOfFunctions));
        DWORD *names = (DWORD *) (base + rva_to_off(exp_dir->AddressOfNames));
        WORD *ordinals = (WORD *) (base + rva_to_off(exp_dir->AddressOfNameOrdinals));

        ok("export table: %lu names, %lu funcs, Base: %lu", (unsigned long) exp_dir->NumberOfNames,
           (unsigned long) exp_dir->NumberOfFunctions, (unsigned long) exp_dir->Base);

        for (int index = 0; index < exp_dir->NumberOfNames; index++) {
            char *name = (char *) base + rva_to_off(names[index]);
            printf("    " ANSI_GRAY "\\___" ANSI_RESET " %s\n", name);
        }
    } else
        error("there is no export table");


    info("parsing import table");
    IMAGE_DATA_DIRECTORY *imp_dd = &dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (imp_dd->VirtualAddress && imp_dd->Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR *imp_dir = (IMAGE_IMPORT_DESCRIPTOR *) (base + rva_to_off(imp_dd->VirtualAddress));

        ok("import table:");
        for (; imp_dir->Name; imp_dir++) {
            ok("DLL: " ANSI_YELLOW "%s" ANSI_RESET, (const char *) (base + rva_to_off(imp_dir->Name)));
            DWORD thunk_rva = imp_dir->OriginalFirstThunk ? imp_dir->OriginalFirstThunk : imp_dir->FirstThunk;

            if (is64) {
                const IMAGE_THUNK_DATA64 *th = (const IMAGE_THUNK_DATA64 *) (base + rva_to_off(thunk_rva));

                for (; th->u1.AddressOfData; ++th) {
                    ULONGLONG v = th->u1.Ordinal;

                    if (IMAGE_SNAP_BY_ORDINAL64(v)) {
                        printf("    " ANSI_GRAY "\\___" ANSI_RESET " #%-5llu\n",
                               (unsigned long long) IMAGE_ORDINAL64(v));
                    } else {
                        const IMAGE_IMPORT_BY_NAME *ibn =
                                (const IMAGE_IMPORT_BY_NAME *) (base + rva_to_off((DWORD) th->u1.AddressOfData));
                        printf("    " ANSI_GRAY "\\___" ANSI_RESET " %s\n", (const char *) ibn->Name);
                    }
                }
            } else {
                const IMAGE_THUNK_DATA32 *th = (const IMAGE_THUNK_DATA32 *) (base + rva_to_off(thunk_rva));

                for (; th->u1.AddressOfData; ++th) {
                    DWORD v = th->u1.Ordinal;

                    if (IMAGE_SNAP_BY_ORDINAL32(v)) {
                        printf("    \\___ #%-5u\n", (unsigned) IMAGE_ORDINAL32(v));
                    } else {
                        const IMAGE_IMPORT_BY_NAME *ibn =
                                (const IMAGE_IMPORT_BY_NAME *) (base + rva_to_off(th->u1.AddressOfData));
                        printf("    \\___ %s\n", (const char *) ibn->Name);
                    }
                }
            }
        }
    } else
        error("there is no import table");

    return EXIT_SUCCESS;
}
