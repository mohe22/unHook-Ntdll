#include "./Unhooker.h"
using namespace std;

wstring GetSystemDirectoryPath()
{
    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    return wstring(systemDir) + L"\\ntdll.dll";
}

vector<BYTE> LoadCleanNtdll()
{
    wstring path = GetSystemDirectoryPath();

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        cerr << "[-] Failed to open file: " << GetLastError() << endl;
        return {};
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        cerr << "[-] Failed to get file size: " << GetLastError() << endl;
        CloseHandle(hFile);
        return {};
    }

    vector<BYTE> buffer(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        cerr << "[-] Failed to read file: " << GetLastError() << endl;
        CloseHandle(hFile);
        return {};
    }

    CloseHandle(hFile);
    return buffer;
}

pair<DWORD, DWORD> GetSectionInfo(BYTE *base, const char *sectionName, bool isLoadedModule)
{
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        cerr << "[-] Invalid DOS signature" << endl;
        return {0, 0};
    }

    PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        cerr << "[-] Invalid NT signature" << endl;
        return {0, 0};
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section)
    {
        char name[9] = {0};
        strncpy_s(name, (char *)section->Name, 8);
        if (strcmp(name, sectionName) == 0)
        {
            DWORD offset = isLoadedModule ? section->VirtualAddress : section->PointerToRawData;
            DWORD size = section->SizeOfRawData;
            return {offset, size};
        }
    }

    cerr << "[-] Section '" << sectionName << "' not found" << endl;
    return {0, 0};
}

bool UnhookNtdll()
{
    cout << "[+] Unhooking ntdll.dll..." << endl;

    // Get in-memory ntdll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        cerr << "[-] Failed to get ntdll handle: " << GetLastError() << endl;
        return false;
    }

    // Get .text section info from memory module
    auto [loadedOffset, loadedSize] = GetSectionInfo((BYTE *)hNtdll, ".text");
    if (!loadedOffset || !loadedSize)
    {
        cerr << "[-] Failed to find .text section in memory" << endl;
        return false;
    }
    BYTE *loadedTextBase = (BYTE *)hNtdll + loadedOffset;
    cout << "[+] Memory .text section: " << static_cast<void *>(loadedTextBase)
         << " | Size: 0x" << hex << loadedSize << dec << endl;

    // Load clean ntdll from disk
    vector<BYTE> cleanNtdll = LoadCleanNtdll();
    if (cleanNtdll.empty())
        return false;

    // Get .text section info from disk image
    auto [cleanOffset, cleanSize] = GetSectionInfo(cleanNtdll.data(), ".text", false);
    if (!cleanOffset || !cleanSize)
    {
        cerr << "[-] Failed to find .text section in disk image" << endl;
        return false;
    }

    // Validate section sizes match
    if (loadedSize != cleanSize)
    {
        cerr << "[-] Size mismatch: memory=0x" << hex << loadedSize
             << " disk=0x" << cleanSize << dec << endl;
        return false;
    }

    // Validate disk section bounds
    if (cleanOffset + cleanSize > cleanNtdll.size())
    {
        cerr << "[-] Clean section exceeds file bounds" << endl;
        return false;
    }

    BYTE *cleanTextBase = cleanNtdll.data() + cleanOffset;
    cout << "[+] Disk .text section: " << static_cast<void *>(cleanTextBase)
         << " | Size: 0x" << hex << cleanSize << dec << endl;

    // Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(loadedTextBase, loadedSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        cerr << "[-] VirtualProtect failed: " << GetLastError() << endl;
        return false;
    }
    cout << "[+] Memory protection changed to RWX" << endl;

    // Restore original code
    memcpy(loadedTextBase, cleanTextBase, loadedSize);
    cout << "[+] .text section restored" << endl;

    // Flush instruction cache
    if (!FlushInstructionCache(GetCurrentProcess(), loadedTextBase, loadedSize))
    {
        cerr << "[-] FlushInstructionCache failed: " << GetLastError() << endl;
        return false;
    }

    // Restore original protection
    DWORD temp;
    if (!VirtualProtect(loadedTextBase, loadedSize, oldProtect, &temp))
    {
        cerr << "[-] Failed to restore protection: " << GetLastError() << endl;
        return false;
    }
    cout << "[+] Protection restored" << endl;

    cout << "[+] Unhooking successful!" << endl;
    return true;
}

int main()
{
    if (!UnhookNtdll())
    {
        return 1;
    }

    return 0;
}

