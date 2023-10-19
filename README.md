
## Introduction

Native Windows code is overwhelmingly position-dependant. This is the case for a multitude of reasons, including legacy support, performance, and simplicity. On the other hand, this simultaneously introduces challenges for both attack and defense. For what is now decades, Windows malware has often required some degree of position independence, especially in shellcode and first-stage payloads. Additionally, due to issues of stealth and evasion, malware must frequently work without the aid of conveniences offered by the operating system and external libraries. Examples include the typical utilities that allow dynamic dependency resolution.

This article reviews standard methods for retrieving module base addresses and introduces two new methods that do not rely on API calls or the Process Environment Block (PEB){{< footnote >}}Unless otherwise noted, all testing was performed on Windows 10 19045 with the bottom-up randomization and high-entropy ASLR enabled.{{< /footnote >}}. These are introduced as *Module Discovery by Code Traversal* and *Module Discovery by Heuristic Stack Analysis.* These methods only rely on information available to the running code and are suitable for use under certain circumstances where access to API calls or the Process Environment Block is impossible or unwanted. The methods do have their own limitations, but are fairly simple and have unique advantages and disdavantages in certain situations.

## Method Review

***GetModuleHandle***

In native Windows code, the most basic method of retrieving a module base is using the Windows API `GetModuleHandle`. When called, this function does one of two things:

1. If passed a `NULL` argument, get the current image base from a global variable referencing the Process Environment Block data structure (PEB) and accessing the offset `0x10` , correlating to `PPEB->ImageBase` (Windows 10 19045) and return the address.
2. Call a second function from `ntdll` to locate and return the image base of a separate module.

In the second case, `GetModuleHandle` will call `LdrGetDllHandle`.`LdrGetDllHandle` lives in `ntdll` and itself diverts to `LdrGetDllHandleEx`. This will kick of a series of calls that will eventually access the PEB to get the module base by name or path.

The conventional wisdom in malware writing is to be wary of carelessly using such procedures, because at any point in the call chain, defense tools may have inserted some sort of monitoring hook. Instead, malware authors very often opt to implement the process manually.

***Manual Module Resolution by PEB Traversal***

On x64 Windows, the PEB is a data structure accessible using the `gs` segment register. The structure contains a linked list of loaded modules and their associated information. It is therefore possible to manually traverse the data structure from user code to retrieve loaded module information.

1. Retrieve the Process Environment Block (PEB) from `gs:0x60`.
2. Obtain the head of the `InMemoryOrderModuleList` from the `LoaderData` of the PEB.
3. Initialize a loop starting from the first entry in the `InMemoryOrderModuleList`, iterating through the list until it loops back to the head.
4. In each iteration, compute the address of the current module's `LDR_MODULE` structure based on the list entry address.
5. Check if the `BaseDllName.Buffer` of the `LDR_MODULE` is not `NULL`:
  - If it is not `NULL`, convert the name to a character string.
  - Compare the names and return `BaseAddress` is they match
6. Move to the next list entry.

## Monitoring of Module Base Retrieval Methods

***API Hooking and Behavior Monitoring***

The most straightforward way of monitoring attempts to retrieve module base addresses would be with usermode hooks on the Windows and NT API procedures. One example of a behavioral check would involve checking if the `GetModuleHandle` call is in proximity to a `GetProcAddress` call, indicating dynamic API import.

***PEB Access Monitoring***

Through emulation or debugging, it is possible to monitor access to the PEB or TEB {{< reference content="https://github.com/mandiant/speakeasy" >}}. With these tools, access to PEB memory is straightforward to detect.

***Static Signatures***

Finally, a very simple detection for code accessing the PEB or TEB is to match suspicious code to a pattern matching a move operation with the x86_64 segment override prefix for the `gs ` segment register. An example pattern would be something like:
```
65 * 8b 04 25 60 00 00 00 00 ; PEB access using 0x65 segment override prefix
65 * 8b 04 25 30 00 00 00 00 ; TEB access using 0x65 segment override prefix
```

## ASLR Analysis

One challenge in locating modules without the aid of conventional resources is ASLR. Microsoft introduced its first Windows implementation of ASLR with Windows Vista in 2007{{< reference content="https://en.wikipedia.org/wiki/Address_space_layout_randomization" citation="" >}}. Microsoft's implementation differs from others due to several reasons. As a result, randomization of module addresses is less complete than that on Linux{{< reference content="https://www.mandiant.com/resources/blog/six-facts-about-address-space-layout-randomization-on-windows" citation="" >}}. This, among other peculiarities of Windows ASLR, introduces weaknesses that can be be taken advantage of by exploit and malware developers. 

***Slide Reuse Across Processes with Same Name***

In a given system session, the first spawn of a process with a unique name results in the assignment of a randomized load location. However, repeated spawns of a process with the same name will reuse the given address. For example, if a process is quickly crashed and reopened, the same module base may be assigned. If the process is renamed for whatever reason, the base may be different, however.

***Shared Module Base Address Reuse Across Session***

In a given system session, system modules like `ntdll` and `kernel32` will be often be loaded into the same location across processes.

***Address Range Predictability***

Despite ASLR, system modules will be loaded in a predictable range of addresses, usually around `0x00007FF000000000`. Though there is still a large range of potential addresses, we can reliably predict the general location of system modules. Address candidates can be compared to the bitmask `0x00007FF000000000` as a crude way to help predict their validity.

***Memory Traversal via Instruction Pointer***

When its possible obtain information about the instruction pointer, the code of the running application can be parsed for the DOS MZ signature. From here, addresses within dynamic modules can be located from the PE headers.

### Observations on System Module Address Predictibility

On a test system, a test harness was written to spawn 200 unique processes. Each process calls back to the parent over a TCP socket with with its `kernel32`, `ntdll`, and main image load addresses. The names of the executable images are modified before spawn to force the `.exe` data to be loaded to a new base address for each process.

Across population sizes of 100 and 200 processes, the distribution of distances between main module, kernel32, and ntdll was found to be uniform. This is expected, as ASLR uses cryptographic methods to assign load addresses. More interestingly, however, the following observations were recorded:

***Run 1***

| Module   | Mean Distance | Standard Deviation |
| -------- | ------------- | ------------------ |
| Kernel32 | 0x886c875c3   | 0x94f56cf4         |
| Ntdll    | 0x8872d75c3   | 0x94f56cf4         |

Kolmogorov-Smirnov p-value for `kernel32`: 0.0

***Run 2***

| Module   | Mean Distance | Standard Deviation |
| -------- | ------------- | ------------------ |
| Kernel32 | 0x87f7fc148   | 0x944cfded         |
| Ntdll    | 0x87fe4c148   | 0x944cfded         |

Kolmogorov-Smirnov p-value for `kernel32`: 0.0

The standard deviation values indicate a consistent spread of address ranges between a process main module and its `kernel32` and `ntdll` system libraries. This serves as proof of the confinement of module locations within specific address ranges, at least on the testing build of Windows 10. A rough limit of distance between user executables and system modules of `0x94a13570` has been observed across two experiment runs with a population size of 200 processes each. In the context of this paper, this limit can be used assist with the prediction of valid addresses from any location within a user executable's code segment. Though I've found it to be too tedious to derive a mean load address for system DLLs, a single observed location can be used with the identified spread to fairly reliably predict a valid system DLL address.

## New Methods for Module Discovery

#### Method 1: Module Discovery by Code Traversal
 
Given the assumption that the address is within a portable executable image in the current process memory, we can easily search backwards in memory for the base address of the module. If that module explicitly imports any functions from external dynamic libraries, the PE headers may be parsed to retrieve an address inside that module and then find its own module base. This can be repeated for every loaded module in the process.

```c++
INT main()
{
    BOOL        OK              = FALSE;
    INT         Distance        = NULL;
    QWORD_PTR   RIP             = NULL;
    QWORD_PTR   MzLoc           = NULL;
    QWORD_PTR   SearchAddr      = NULL;
    QWORD_PTR   BaseAddr        = NULL;

    BYTE MzSig[5] = { 0x4D, 0x5A, 0x90, 0x00, 0x03 };

    // 1. Get the instruction pointer (or in this case, an approximation it)
    RIP = GetInstructionPointer();
   
    // 2. Find the DOS signature of the current module
    SearchAddr = (QWORD_PTR)FindByteSig(
        RIP, MzSig, sizeof(MzSig), 0xFFFF0, TRUE, &Distance);
    if (!SearchAddr) return ERROR_NOT_FOUND;

    // 3. Find the first Kernel32 import from IAT
    SearchAddr = FindFirstModuleImport((PBYTE)SearchAddr, HASH_K32);
    if (!SearchAddr) return ERROR_NOT_FOUND;

    // 4. Find kernel32 base from the export
    SearchAddr = (QWORD_PTR)FindByteSig(
        SearchAddr, MzSig, sizeof(MzSig), 0xFFFFF, TRUE, &Distance);
    if (!SearchAddr) return ERROR_NOT_FOUND;

    // 5. Get address inside ntdll
    SearchAddr = FindFirstModuleImport((PBYTE)SearchAddr, HASH_NTDLL);
    if (!SearchAddr) return ERROR_NOT_FOUND;

    // 6. Get ntdll base
    BaseAddr = (QWORD_PTR)FindByteSig(
        SearchAddr, MzSig, sizeof(MzSig), 0xFFFFF, TRUE, &Distance);

    return ERROR_SUCCESS;
}
```

***Method 1 Advantages***

This method is *almost* as robust at enabling module discovery as standard methods such as `GetModuleHandle` or using the PEB. The entire list of modules that are specified in a given executable's headers may be resolved without calling any APIs or accessing the PEB.

***Method 1 Disdvantages***

The main downside of this method compared to traditional means is that modules loaded at runtime will not be discoverable merely by searching through the known import directories. Additionally, this method requires knowledge of an address backed by a PE image. This means that shellcode threads will need to be provided this information. Finally, there is room for error in the pattern matching and PE format parsing.


#### Method 2: Module Discovery by Heuristic Stack Analysis

The main challenge in leveraging the thread stack to identify system modules is in the risk of read-access violations. The stack can contain all sorts of data that might look like valid addresses which will trigger access violations on read. However, given our knowledge of the constraints on variability of system module locations, we can devise a simple means to predict whether an address is valid before we try to read the memory at that location.

The general algorithm is as follows:

1. Obtain Stack Pointer: Fetch the stack pointer that will serve as the starting point for the search. Return an error if this step fails.

2. Loop to Search: Enter a loop to traverse the stack, checking each value for likelihood of being a system DLL address

3. Additional Validation: Attempt to find the DOS MZ signature from the candidate location. If we are incorrect in our prediction that the given address is valid, this may trigger an access violation

4. Module Name Validation: Once a valid module base has been found, traverse its headers and see if it's reported name hash matches the target.

```

// Metrics for address prediction
#define SYSTEM_DLL_LOWER_BOUND  0x00007FF000000000ULL
#define SYSTEM_DLL_UPPER_BOUND  0xFFFF800000000000ULL
#define MEAN_DISTANCE           0x8872D75C3ULL
#define STANDARD_DEVIATION      0x94F56CF4ULL
#define REFERENCE_KERNEL32_LOC  0x7FFF91720000ULL
#define REFERENCE_NTDLL_LOC     0x7FFF91D70000ULL

BOOL PredictValidSystemDllRange(QWORD Address, QWORD ReferenceLoc) 
{
    // Check if the address falls within the typical range for system DLLs
    if (Address <= SYSTEM_DLL_LOWER_BOUND || Address >= SYSTEM_DLL_UPPER_BOUND) 
    {
        return FALSE;
    }

    // Calculate bounds based on mean and standard deviation
    QWORD LowerLimit = ReferenceLoc - STANDARD_DEVIATION;
    QWORD UpperLimit = ReferenceLoc + STANDARD_DEVIATION;

    if (Address >= LowerLimit && Address <= UpperLimit) 
    {
        return TRUE;
    }

    return FALSE;
}

INT main()
{
    BOOL        OK            = FALSE;
    SIZE_T      StackOffset   = NULL;
    QWORD_PTR   RSP           = NULL;
    QWORD_PTR   MzLoc         = NULL;
    QWORD_PTR   SearchAddr    = NULL;
    QWORD_PTR   BaseAddress   = NULL;

    BYTE MzSig[24]  = {
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // 1. Get the stack pointer
    // On thread entry, this might be something close to the target base 
    // address, but for anything wrapped in the runtime (like this demo)
    // will have to look a bit harder.
    RSP = GetStackPointer();
    if (!RSP) return ERROR_NOT_FOUND;
    SearchAddr = (QWORD_PTR)*RSP;

    // 2. Walk the stack
    // Check each value on the stack for likelihood that it is within the range
    // of normal system DLL allocation addresses.
    for (StackOffset = 0; StackOffset < 0xFFF;)
    {
    _stackwalk:
        if (StackOffset > 0xFFF) goto _failure;
        SearchAddr = (QWORD_PTR)*(RSP + (-1*StackOffset));
        OK = PredictValidSystemDllRange(
            (QWORD)SearchAddr, REFERENCE_NTDLL_LOC);
        StackOffset += 8;
        if (OK) break;
    }

    if (!OK) return ERROR_NOT_FOUND;

    // 3. Search for the MZ signature in the target address. If we predicted
    // incorrectly, this will likely trigger an access violation.
    BaseAddress = (QWORD_PTR)FindByteSig(
        (PVOID)SearchAddr, MzSig, sizeof(MzSig), 0xFFFFFF, TRUE);
    // If we survived but failed to find MZ signature, continue searching
    if (!BaseAddress) goto _stackwalk; 

    // 4. Check the name of the image by its Optional header
    // If we did not crash, we found a valid DOS header in the system DLL 
    // address space. We are likely looking at one of the DLLs we want.
    OK = CheckModNameByExportDir((PBYTE)BaseAddress, HASH_NTDLL);

    // 5. If we didn't find it the first time, we can just continue the walk.
    // The stack walk in this demo restricts the search to RSP-0xFFF
    if (!OK) goto _stackwalk;

    return ERROR_SUCCESS;
_failure:
    return ERROR_NOT_FOUND;
}
```

***Method 2 Advantages***

The unique advantage of this method is that it relies *only* on the program stack. Even in the presence of ASLR, system DLL addresses can be predicted with some reliability. New threads begin with `ntdll!RtlUserThreadStart` followed by `KERNEL32!BaseThreadInitThunk`. Therefore it should be possible to obtain base addresses of both modules using this method. This method does not rely on any information or requirements external to the running thread such as external APIs, PEB information, or a known code location (as in Method 1). This method can also be combined with Method 1 to locate other modules after one has been located from the stack.

***Method 2 Disadvantages***

The most obvious downside of this method is the potential for reading an invalid memory location and crashing the program. This is doubly bad because such a crash could lead to additional scrutiny that might not otherwise be had. Further refinement in the prediction method may be possible to reduce the likelihood of such events.  As with Method 1, this method does not include discovery of libraries loaded at runtime.

## Proof-of-Concept: PEB-Less GetModuleHandle

The following code offers a complete demonstration of a `GetModuleHandle`-alike function which uses Method 1 to locate module base addresses from a known code location (in this case `RIP`). The code will recursively search accessible module import information for the given DLL name. At no point is the PEB accessed and no API calls are used.

```c++
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

    return PeblessFindModuleRecursively(
        StartAddr, szModuleName, Visited, &nVisited);
}

// Program entry point
INT main()
{
    PVOID ModuleHandle = PeblessGetModuleHandle((PCHAR)"ntdll.dll");

    return 0;
}
```


## Conclusion

This article presented an analysis of the standard methods used to retrieve module base addresses in native Windows code, including the widely-used `GetModuleHandle`` API and manual module resolution through the Process Environment Block (PEB). It also introduced two novel methods—-*Module Discovery by Code Traversal* and *Module Discovery by Heuristic Stack Analysis*-—as alternatives that are robust yet do not rely on API calls or the PEB. Both methods offer unique advantages and disadvantages, depending on the constraints and requirements of the situation. Additionally, this work evaluated the challenges posed by Address Space Layout Randomization (ASLR) and proposed ways to work around them.

***Suggestions for Future Work***

1. Robustness Evaluation: More thorough testing could be conducted across different versions of Windows and in combination with other evasion techniques to evaluate the robustness of the new methods.

2. Optimization: Both methods could be optimized for performance and safety. The stack-based approach, in particular, has the downside of potentially triggering read-access violations, so research could be aimed at refining the validation technique to minimize this risk.

3. Detection Techniques: New methods for detecting these PEB-less techniques should be investigated. Since they don’t rely on the PEB or make API calls, traditional hooking methods will not be effective.

