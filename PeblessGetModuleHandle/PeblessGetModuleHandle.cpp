#include <Windows.h>

// Convenience types
#define QWORD                   DWORD64
#define QWORD_PTR               DWORD64 *

#define MAX_VISITED             124

extern "C" QWORD_PTR GetInstructionPointer();

// Find the first instance of a matching byte sequence with directionality
PVOID FindByteSig(PVOID SearchBase, PVOID Sig, INT EggSize, INT Bound, BOOL Rev)
{
    if (!Rev)
    {
        for (INT i = 0; i < Bound; i++)
        {
            if (!memcmp(&((PBYTE)SearchBase)[i], Sig, EggSize))
            {
                return &((PBYTE)SearchBase)[i];
            }
        }
    }
    else {
        for (INT i = 0; i < Bound; i++)
        {
            if (!memcmp(&((PBYTE)SearchBase)[-i], Sig, EggSize))
            {
                return &((PBYTE)SearchBase)[-i];
            }
        }
    }

    return NULL;
}

// Compare a module's reported name (Optional directory) to a string
BOOL CheckModNameByExportDir(PBYTE BaseAddr, PCHAR ModName)
{
    DWORD                   ExportDirRVA    = NULL;
    DWORD                   NameRVA         = NULL;
    PCHAR                   Name            = NULL;
    SIZE_T                  NameLength      = NULL;
    PIMAGE_DOS_HEADER       pDosHeader      = NULL;
    PIMAGE_NT_HEADERS       pNtHeaders      = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir      = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)BaseAddr;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    pNtHeaders = (PIMAGE_NT_HEADERS)(BaseAddr + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    ExportDirRVA = pNtHeaders->OptionalHeader.
        DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (ExportDirRVA == 0) return FALSE;

    pExportDir = (PIMAGE_EXPORT_DIRECTORY)(BaseAddr + ExportDirRVA);

    NameRVA = pExportDir->Name;
    if (NameRVA == 0) {
        return FALSE; // No name
    }

    Name = (PCHAR)(BaseAddr + NameRVA);
    NameLength = strlen(Name);

    if (strcmp(ModName, Name) == 0)
    {
        return TRUE;
    }
    
    return FALSE;
}

// Given a base address, find the first import from a given DLL
QWORD_PTR FindFirstModuleImport(PBYTE MzLoc, PCHAR ModName)
{
    CHAR                        CurrentName[MAX_PATH];
    PIMAGE_DOS_HEADER           pDosHeader = NULL;
    PIMAGE_NT_HEADERS           pNtHeaders = NULL;
    PIMAGE_OPTIONAL_HEADER      pOptHeader = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    pImportDesc = NULL;
    PCHAR                       pImportName = NULL;
    PIMAGE_THUNK_DATA           pThunk = NULL;
    PIMAGE_THUNK_DATA           pIATThunk = NULL;

    // Initialize locals
    pDosHeader = (PIMAGE_DOS_HEADER)MzLoc;

    // Validate DOS header
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Initialize NT Headers
    pNtHeaders = (PIMAGE_NT_HEADERS)(MzLoc + pDosHeader->e_lfanew);

    // Validate PE header
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Initialize Optional Header
    pOptHeader = &pNtHeaders->OptionalHeader;

    // Initialize Import Descriptor
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
        MzLoc
        + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        .VirtualAddress);

    while (pImportDesc && pImportDesc->Name)
    {
        pImportName = (PCHAR)(MzLoc + pImportDesc->Name);

        if (pImportName)
        {
            strcpy_s(CurrentName, sizeof(CurrentName), pImportName);
            for (int i = 0; CurrentName[i]; i++) {
                CurrentName[i] = (CHAR)tolower((unsigned char)CurrentName[i]);
            }
            if (strcmp(CurrentName, ModName) == 0)
            {
                // Get the OriginalFirstThunk
                pThunk = (PIMAGE_THUNK_DATA)(
                    MzLoc + pImportDesc->OriginalFirstThunk);
                // Get the corresponding entry in the IAT
                pIATThunk = (PIMAGE_THUNK_DATA)(
                    MzLoc + pImportDesc->FirstThunk);

                if (pThunk && pIATThunk) // Check if thunks are valid
                {
                    // Return the full VA of the first function
                    return (QWORD_PTR)(pIATThunk->u1.Function);
                }
            }
        }
        pImportDesc++;
    }

    return NULL;
}
// Function to check if a module has already been visited
bool IsModuleVisited(PVOID* Visited, int nVisited, PVOID ModBase) {
    for (int i = 0; i < nVisited; i++) {
        if (Visited[i] == ModBase) {
            return true;
        }
    }
    return false;
}

PVOID PeblessFindModuleRecursively(
    PBYTE   StartAddr, 
    PCHAR   ModName, 
    PVOID*  Visited, 
    PINT    nVisited) 
{
    DWORD                       ImportDirRVA            = NULL;    
    PCHAR                       pModuleName             = NULL;
    PVOID                       FirstImport             = NULL;
    PVOID                       FoundBase               = NULL;
    PIMAGE_DOS_HEADER           pDosHeader              = NULL;
    PIMAGE_NT_HEADERS           pNtHeaders              = NULL;
    PIMAGE_OPTIONAL_HEADER      pOptionalHeader         = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    pImportDesc             = NULL;
    CHAR                        CurrentName[MAX_PATH] = { NULL };

    BYTE MzSig[5] = { 0x4D, 0x5A, 0x90, 0x00, 0x03 };
        

    if (IsModuleVisited(Visited, *nVisited, StartAddr)) {
        return NULL;  // Avoid infinite recursion
    }

    Visited[*nVisited] = StartAddr;
    (*nVisited)++;

    if (CheckModNameByExportDir(StartAddr, ModName)) {
        return StartAddr;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)StartAddr;
    pNtHeaders = (PIMAGE_NT_HEADERS)(StartAddr + pDosHeader->e_lfanew);
    pOptionalHeader = &pNtHeaders->OptionalHeader;
    ImportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(StartAddr + ImportDirRVA);

    while (pImportDesc->Name) {
        pModuleName = (char*)(StartAddr + pImportDesc->Name);
        strcpy_s(CurrentName, sizeof(CurrentName), pModuleName);
        for (INT i = 0; CurrentName[i]; i++) {
            CurrentName[i] = (CHAR)tolower((unsigned char)CurrentName[i]);
        }

        FirstImport = FindFirstModuleImport(StartAddr, CurrentName);
        if (!FirstImport) {
            pImportDesc++;
            continue;
        }

        FoundBase = FindByteSig(
            FirstImport, MzSig, sizeof(MzSig), 0xFFFFF, TRUE);

        if (FoundBase) {
            FoundBase = PeblessFindModuleRecursively(
                (PBYTE)FoundBase, ModName, Visited, nVisited);
            if (FoundBase) {
                return FoundBase;
            }
        }

        pImportDesc++;
    }

    return NULL;
}

// Get a module base address without using the PEB
// NOTE: Does not locate libraries loaded with LoadLibrary
PVOID PeblessGetModuleHandle(PCHAR szModuleName) {
    PVOID   Visited[MAX_VISITED]    = { NULL };
    PBYTE   StartAddr       = NULL;
    INT     nVisited        = 0;
    BYTE    MzSig[5]        = { 0x4D, 0x5A, 0x90, 0x00, 0x03 };

    QWORD_PTR RIP = (QWORD_PTR)GetInstructionPointer();

    StartAddr = (PBYTE)FindByteSig(
        (PVOID)RIP, MzSig, sizeof(MzSig), 0xFFFFF, TRUE);

    if (szModuleName == NULL) return StartAddr;

    return PeblessFindModuleRecursively(
        StartAddr, szModuleName, Visited, &nVisited);
}

// Program entry point
INT main()
{
    PVOID BaseNtdll = PeblessGetModuleHandle((PCHAR)"ntdll.dll");
    if (!BaseNtdll) return ERROR_NOT_FOUND;

    PVOID BaseCurrent = PeblessGetModuleHandle(NULL);
    if (!BaseCurrent) return ERROR_NOT_FOUND;

    return 0;
}