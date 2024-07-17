// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <cstring>
#include <vector>
#include <fstream>
#include <string>
#include <atlbase.h>
#include <atlconv.h>
#include <inttypes.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <memoryapi.h>
#include <algorithm>
#include <winternl.h>
#include <winnt.h>
#include <iomanip>
#include <thread>
#include <xstring>
#include <shellapi.h>

char* pointerToArgvListAnsi = NULL;
char* argvListAnsi[100] = { nullptr };
wchar_t* pointerToArgvListWchar = NULL;
wchar_t* argvListWchar[100] = { nullptr };
int argC = 0;

PIMAGE_TLS_CALLBACK* callbacks = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

LPVOID AllocateMemoryForProcess_PreferImageBase(IMAGE_NT_HEADERS* NtHeader) {
    LPVOID imageAtImageBase = VirtualAlloc(LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (imageAtImageBase != NULL) {
        return imageAtImageBase;
    }

    LPVOID imageAtRelocatedBase = VirtualAlloc(NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return imageAtRelocatedBase;
}

LPWSTR WINAPI hookGetCommandLineW() {
    return pointerToArgvListWchar;
}
LPSTR WINAPI hookGetCommandLineA() {
    return pointerToArgvListAnsi;
}

int* __cdecl Hook__p___argc(void) {
    return &argC;
}

char*** __cdecl Hook__p___argv(void) {
    static char** argv = argvListAnsi;
    return &argv;
}

// These 2 functions are untested, there is a chance they will not work (as did other code copied from the same remote repository)
int Hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless) {
    *_Argc = argC;
    *_Argv = (wchar_t**)argvListWchar;
    return 0;
}
int Hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless) {
    *_Argc = argC;
    *_Argv = (char**)argvListAnsi;
    return 0;
}

bool LoadLibraries(IMAGE_NT_HEADERS* NtHeader, DWORD64 imageBase)
{
    IMAGE_DATA_DIRECTORY importDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDirectory.Size == 0) {
        return false;
    }

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(imageBase + importDirectory.VirtualAddress);
    while (importDescriptor->Name) {
        char* dllName = (char*)(imageBase + importDescriptor->Name);
        bool selfImport = false;
        HMODULE dllModule = GetModuleHandleA(dllName);
        if (!dllModule) {
            // If GetModuleHandleA returns NULL, the DLL is not already loaded -> load it.
            dllModule = LoadLibraryA(dllName);
            if (!dllModule) {
                std::cerr << "Failed to load DLL: " << dllName << std::endl;
                return false;
            }

            //std::cout << "Loaded DLL: " << dllName << std::endl;
        }
        else {
            //std::cout << "DLL already known: " << dllName << std::endl;
            selfImport = true;
        }

        IMAGE_THUNK_DATA* originalFirstThunk = PIMAGE_THUNK_DATA(imageBase + importDescriptor->OriginalFirstThunk);
        IMAGE_THUNK_DATA* firstThunk = PIMAGE_THUNK_DATA(imageBase + importDescriptor->FirstThunk);

        while (originalFirstThunk->u1.AddressOfData) {
            if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                DWORD ordinal = IMAGE_ORDINAL(originalFirstThunk->u1.Ordinal);
                firstThunk->u1.Function = (DWORD_PTR)GetProcAddress(dllModule, MAKEINTRESOURCEA(ordinal));
                if (selfImport) {
                    std::cout << "Self-Imported " << dllName << "->" << ordinal << std::endl;
                }
                else {
                    std::cout << "Imported " << dllName << "->" << ordinal << std::endl;
                }
            }
            else {
                // Import by name
                IMAGE_IMPORT_BY_NAME* importByName = PIMAGE_IMPORT_BY_NAME(imageBase + originalFirstThunk->u1.AddressOfData);
                bool hooked = true;
                if (_strcmpi(importByName->Name, "GetCommandLineA") == 0) {
                    firstThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (_strcmpi(importByName->Name, "GetCommandLineW") == 0) {
                    firstThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (_strcmpi(importByName->Name, "__wgetmainargs") == 0) { // the getmainargs functions are untested.
                    firstThunk->u1.Function = (size_t)Hook__wgetmainargs;
                }
                else if (_strcmpi(importByName->Name, "__getmainargs") == 0) {
                    firstThunk->u1.Function = (size_t)Hook__getmainargs;
                }
                else if (_strcmpi(importByName->Name, "__p___argc") == 0) {

                    firstThunk->u1.Function = (DWORD64)&Hook__p___argc;
                }
                else if (_strcmpi(importByName->Name, "__p___argv") == 0) {
                    firstThunk->u1.Function = (DWORD64)&Hook__p___argv;
                }
                else {
                    firstThunk->u1.Function = (DWORD_PTR)GetProcAddress(dllModule, importByName->Name);
                    hooked = false;
                }

                if (hooked) {
                    std::cout << "Hooked " << dllName << "->" << importByName->Name << std::endl;
                }
                else {
                    if (selfImport) {
                        std::cout << "Self-Imported " << dllName << "->" << importByName->Name << std::endl;
                    }
                    else {
                        std::cout << "Imported " << dllName << "->" << importByName->Name << std::endl;
                    }
                }
            }

            if (!firstThunk->u1.Function) {
                std::cerr << "Failed to get function address." << std::endl;
                return false;
            }

            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }

    return true;
}

bool Relocate(IMAGE_NT_HEADERS* NtHeader, DWORD64 imageBase, DWORD64 relocationDelta) {
    IMAGE_DATA_DIRECTORY& relocDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relocDir.Size == 0) {
        return false;
    }

    DWORD64 relocTable = imageBase + relocDir.VirtualAddress;
    while (relocTable < (imageBase + relocDir.VirtualAddress + relocDir.Size)) {
        IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)relocTable;
        DWORD numEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocEntries = (WORD*)(relocTable + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < numEntries; i++) {
            WORD type = relocEntries[i] >> 12;
            WORD offset = relocEntries[i] & 0x0FFF;
            DWORD64* address = (DWORD64*)(imageBase + relocation->VirtualAddress + offset);

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *address += relocationDelta;
                break;
            default:
                std::cerr << "Unsupported relocation type: " << std::hex << type << std::endl;
                return false;
            }
        }

        relocTable += relocation->SizeOfBlock;
    }

    return true;
}

bool IsGUIApplication(IMAGE_NT_HEADERS* NtHeader) {
    return NtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
}

void SetFlags(CONTEXT& context, bool setIF, bool setZF, bool setPF) {
    if (setIF) context.EFlags |= (1 << 9);  // Set the Interrupt Flag
    if (setZF) context.EFlags |= (1 << 6);  // Set the Zero Flag
    if (setPF) context.EFlags |= (1 << 2);  // Set the Parity Flag
}

bool ApplyMemoryProtections(IMAGE_NT_HEADERS64* NtHeader, IMAGE_DOS_HEADER* DOSHeader, void* Image, DWORD64 imageBase) {
    IMAGE_SECTION_HEADER* SectionHeader;

    for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++) {
        SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(Image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * sizeof(IMAGE_SECTION_HEADER)));
        LPVOID dest = LPVOID(DWORD64(imageBase) + SectionHeader->VirtualAddress);
        LPVOID src = LPVOID(DWORD64(Image) + SectionHeader->PointerToRawData);
        DWORD64 size = SectionHeader->SizeOfRawData;

        if (size == 0) {
            size = SectionHeader[count].Misc.VirtualSize;
        }

        // Determine the correct memory protection for the section
        DWORD oldProtection;
        DWORD newProtection = PAGE_NOACCESS;
        if (SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
                if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    newProtection = PAGE_EXECUTE_READWRITE;
                }
                else {
                    newProtection = PAGE_EXECUTE_READ;
                }
            }
            else {
                newProtection = PAGE_EXECUTE;
            }
        }
        else {
            if (SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
                if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    newProtection = PAGE_READWRITE;
                }
                else {
                    newProtection = PAGE_READONLY;
                }
            }
            else {
                if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    newProtection = PAGE_WRITECOPY;
                }
                else {
                    newProtection = PAGE_NOACCESS;
                }
            }
        }

        // Set the memory protection
        if (!VirtualProtect(dest, size, newProtection, &oldProtection)) {
            std::cerr << "Failed to set memory protection: " << GetLastError() << std::endl;
            return false;
        }
    }

    return true;
}

PEB* NtCurrentPeb() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}

void SetConstantsForCommandLineHooks(const wchar_t* cmdline) {
    if (!cmdline) return;
    std::wstring sz_wcmdline(cmdline);

    // Allocate and copy wide command line
    pointerToArgvListWchar = new wchar_t[sz_wcmdline.size() + 1];
    lstrcpyW(pointerToArgvListWchar, sz_wcmdline.c_str());

    // Convert to ANSI and copy
    std::string ansiString(sz_wcmdline.begin(), sz_wcmdline.end());
    argvListAnsi[0] = new char[ansiString.size() + 1];
    lstrcpyA(argvListAnsi[0], ansiString.c_str());

    pointerToArgvListAnsi = new char[ansiString.size() + 1];
    lstrcpyA(pointerToArgvListAnsi, ansiString.c_str());

    wchar_t** szArglist = CommandLineToArgvW(cmdline, &argC);
    for (int i = 0; i < argC; i++) {
        argvListWchar[i] = new wchar_t[lstrlenW(szArglist[i]) + 1];
        lstrcpyW(argvListWchar[i], szArglist[i]);

        std::wstring wideString(argvListWchar[i]);
        ansiString = std::string(wideString.begin(), wideString.end());
        argvListAnsi[i] = new char[ansiString.size() + 1];
        lstrcpyA(argvListAnsi[i], ansiString.c_str());
    }
    LocalFree(szArglist); // Free the memory allocated by CommandLineToArgvW
}

void ExecuteTLSCallbacks(BYTE* imageBase, DWORD dwReason) {
    if (callbacks) {
        while (*callbacks) {
            (*callbacks)(imageBase, /*DLL_PROCESS_ATTACH */ dwReason, nullptr);
            callbacks++;
        }
    }
}

extern "C" {
    __declspec(dllexport) int __stdcall RunImage_CreateThread(BYTE* file, const wchar_t* commandLine);
}

__declspec(dllexport) int __stdcall RunImage_CreateThread(BYTE* file, const wchar_t* commandLine) {
    try {
        IMAGE_DOS_HEADER* DOSHeader;
        IMAGE_NT_HEADERS* NtHeader;
        void* Image = file;

        if (Image == nullptr) {
            std::cerr << "Process Image is null" << std::endl;
            return -1;
        }

        DOSHeader = PIMAGE_DOS_HEADER(Image);
        NtHeader = PIMAGE_NT_HEADERS(DWORD64(Image) + DOSHeader->e_lfanew);
        bool requiresRelocation = false;
        SetConstantsForCommandLineHooks(commandLine);

        if (NtHeader->Signature == IMAGE_NT_SIGNATURE) {
            DWORD64 imageBase = (DWORD64)AllocateMemoryForProcess_PreferImageBase(NtHeader);
            if (imageBase != NtHeader->OptionalHeader.ImageBase) {
                requiresRelocation = true;
                std::cout << std::hex << "New image base: " << imageBase << std::endl;
            }
            else {
                std::cout << std::hex << "Mapping with preferred base at " << imageBase << std::endl;
            }

            DWORD64 relocationDelta = imageBase - NtHeader->OptionalHeader.ImageBase;
            NtHeader->OptionalHeader.ImageBase = imageBase;
            memcpy(LPVOID(imageBase), Image, NtHeader->OptionalHeader.SizeOfHeaders);

            for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++) {
                IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(Image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (count * sizeof(IMAGE_SECTION_HEADER)));
                LPVOID dest = LPVOID(imageBase + SectionHeader->VirtualAddress);
                LPVOID src = LPVOID(DWORD64(Image) + SectionHeader->PointerToRawData);
                DWORD64 size = SectionHeader->SizeOfRawData;
                memcpy(dest, src, size);
            }

            if (!LoadLibraries(NtHeader, imageBase)) {
                std::cerr << "LoadLibraries encountered an error" << std::endl;
                return 0x10;
            }

            if (IsGUIApplication(NtHeader)) {
                std::cout << "This is a GUI application" << std::endl;
                //std::thread guiThread(SetupGUIEnvironment);
                //guiThread.detach();
            }

            if (requiresRelocation) {
                if (!Relocate(NtHeader, imageBase, relocationDelta)) {
                    std::cerr << "Relocation(s) failed" << std::endl;
                    return 0x100;
                }
            }

            if (!ApplyMemoryProtections(NtHeader, DOSHeader, Image, imageBase)) {
                std::cerr << "Applying Memory Protections failed" << std::endl;
                return 0x1000;
            }

            std::cout << "Applied Memory Protections" << std::endl;

            PEB* peb = NtCurrentPeb();
            if (peb != NULL) {
                PVOID oldImageBase = peb->Reserved3[1]; // This is ImageBaseAddress in the PEB.
                DWORD oldProtect;
                VirtualProtect(&peb->Reserved3[1], sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                peb->Reserved3[1] = LPVOID(imageBase);
                VirtualProtect(&peb->Reserved3[1], sizeof(PVOID), oldProtect, &oldProtect);

                std::cout << "Old Image Base: " << oldImageBase << std::endl;
                std::cout << "New Image Base: " << peb->Reserved3[1] << std::endl;
            }
            else {
                std::cerr << "Failed to get PEB." << std::endl;
            }

            //NtCurrentTeb();
            DWORD64 entryPoint = imageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;

            HANDLE hNewThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(LPVOID)entryPoint, 0, CREATE_SUSPENDED, NULL);
            if (!hNewThread) {
                std::cerr << "Failed to create thread: " << GetLastError() << std::endl;
                return 0x20;
            }

            PIMAGE_DATA_DIRECTORY tlsDirectory = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tlsDirectory->VirtualAddress != 0) {
                std::cout << "Saving TLS callbacks" << std::endl;
                PIMAGE_TLS_DIRECTORY64 tls = (PIMAGE_TLS_DIRECTORY64)(imageBase + tlsDirectory->VirtualAddress);
                callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
            }
            else {
                std::cout << "No TLS callbacks exist" << std::endl;
            }

            ExecuteTLSCallbacks((BYTE*)imageBase, DLL_PROCESS_ATTACH);

            CONTEXT context;
            ZeroMemory(&context, sizeof(CONTEXT));
            context.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;

            if (!GetThreadContext(hNewThread, &context)) {
                std::cerr << "Failed to get thread context: " << GetLastError() << std::endl;
                CloseHandle(hNewThread);
                return 0x200;
            }

            /*std::cout << "SegGs: " << context.SegGs << std::endl;
            std::cout << "SegSs: " << context.SegSs << std::endl;
            std::cout << "SegCs: " << context.SegCs << std::endl;
            std::cout << "SegDs: " << context.SegDs << std::endl;
            std::cout << "SegFs: " << context.SegFs << std::endl;
            std::cout << "SegEs: " << context.SegEs << std::endl;*/

            context.Rip = entryPoint;
            context.Rcx = entryPoint;
            context.Rdx = entryPoint;
            context.Rsi = entryPoint;
            context.Rdi = entryPoint;
            SetFlags(context, true, true, true);

            if (!SetThreadContext(hNewThread, &context)) {
                std::cerr << "Failed to Set Thread Context: " << GetLastError() << std::endl;
                return 0x2000;
            }

            ResumeThread(hNewThread);
            WaitForSingleObject(hNewThread, INFINITE);
            return 0;
        }
    }
    catch (std::exception e) {
        std::cerr << "An exception occurred: " << e.what() << std::endl;
        return 0xEC;
    }
}