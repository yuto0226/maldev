#include <Windows.h>
#include <winternl.h>
#include <iomanip>
#include <iostream>
#include <vector>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t)(HANDLE ProcessHandle,
                                                     PROCESSINFOCLASS ProcessInformationClass,
                                                     PVOID ProcessInformation,
                                                     ULONG ProcessInformationLength,
                                                     PULONG ReturnLength);

std::string ws2s(std::wstring &wide_string)
{
    if (wide_string.empty()) {
        return "";
    }

    // Determine the size needed for the UTF-8 buffer
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        throw std::runtime_error("Failed to calculate size for UTF-8 string.");
    }

    // Allocate the buffer and perform the conversion
    std::string utf8_string(size_needed - 1, '\0');  // Exclude the null terminator
    WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, &utf8_string[0], size_needed, nullptr, nullptr);

    return utf8_string;
}

std::wstring read_remote_unicode(HANDLE hProcess, UNICODE_STRING *u)
{
    std::vector<wchar_t> data(u->Length / sizeof(wchar_t) + 1, L'\0');

    if (!ReadProcessMemory(hProcess, u->Buffer, data.data(), u->Length, nullptr)) {
        std::cout << "[-] unable read CommandLine, err=" << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return std::wstring();
    }

    std::wstring w;
    w.assign(data.begin(), data.end());

    return w;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "[-] usage: " << argv[0] << "<pid>" << std::endl;
        return EXIT_FAILURE;
    }

    int exit_code = EXIT_SUCCESS;

    DWORD pid = atoi(argv[1]);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
    if (!hProcess) {
        std::cout << "[-] unable open process of pid:" << pid << ", err=" << GetLastError() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "[+] open process (" << pid << ") with handle: 0x" << std::hex << hProcess << std::endl;

    HMODULE ntdll = LoadLibraryA("ntdll");
    if (!ntdll) {
        std::cout << "[-] unable to load ntdll, err=" << GetLastError() << std::endl;
        CloseHandle(hProcess);
        exit(EXIT_FAILURE);
    }

    std::cout << "[+] load ntdll @ 0x" << std::hex << ntdll << std::endl;

    NtQueryInformationProcess_t NtQueryInformationProcess =
            (NtQueryInformationProcess_t) GetProcAddress(ntdll, "NtQueryInformationProcess");

    std::cout << "[+] resolve NtQueryInformationProcess @ 0x" << std::hex << NtQueryInformationProcess << std::endl;

    PROCESS_BASIC_INFORMATION pbi = {0};

    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    std::cout << "[i] PebBaseAddress @ 0x" << std::hex << pbi.PebBaseAddress << std::endl;
    std::cout << "[i] UniqueProcessId: " << pbi.UniqueProcessId << std::endl;

    PEB peb = {0};

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
        std::cout << "[-] unable read peb, err=" << GetLastError() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(ntdll);
        exit(EXIT_FAILURE);
    }

    std::cout << "[i] BeingDebugged: " << (peb.BeingDebugged ? "true" : "false") << std::endl;

    RTL_USER_PROCESS_PARAMETERS param = {0};
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &param, sizeof(param), nullptr)) {
        std::cout << "[-] unable read peb.ProcessParameters, err=" << GetLastError() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(ntdll);
        exit(EXIT_FAILURE);
    }

    std::wstring image = read_remote_unicode(hProcess, &param.ImagePathName);
    std::cout << "[i] ImagePathName: " << ws2s(image) << std::endl;

    std::wstring cmdline = read_remote_unicode(hProcess, &param.CommandLine);
    std::cout << "[i] CommandLine: " << ws2s(cmdline) << std::endl;

CLEAN:
    CloseHandle(hProcess);
    CloseHandle(ntdll);

    return exit_code;
}