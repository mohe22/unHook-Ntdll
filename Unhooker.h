#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
// Function prototypes
std::wstring GetSystemDirectoryPath();
std::vector<BYTE> LoadCleanNtdll();
std::pair<DWORD, DWORD> GetSectionInfo(BYTE *base, const char *sectionName, bool isLoadedModule = true);
bool UnhookNtdll();
