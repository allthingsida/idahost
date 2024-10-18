#pragma once

#include <Windows.h>

class PEMapper 
{
public:
    using ResolveImportProto = bool(*)(void *ud, LPCSTR lib_name, HMODULE lib_handle, LPCSTR sym_name, DWORD64 *addr);

private:
    BYTE* pe_content_;
    size_t pe_size_;
    void* base_ = nullptr;
    DWORD64 entry_point_ = 0;
    bool owns_memory_ = false;
    const char* current_imported_library_ = nullptr;

    ResolveImportProto ResolveImport_ = nullptr;
    void* ResolveImport_ud_ = nullptr;

    IMAGE_NT_HEADERS* GetNtHeaders()
    {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_content_;
        return (IMAGE_NT_HEADERS*)(pe_content_ + dos_header->e_lfanew);
    }

    bool MapPE()
    {
        base_ = AllocateAndMapHeaders();
        if (base_ == nullptr)
            return false;

        if (!MapSections())
            return false;

        if (!LoadImports())
            return false;

        ApplyBaseRelocations();
        SetSectionProtections();

        entry_point_ = GetNtHeaders()->OptionalHeader.AddressOfEntryPoint + (DWORD64)base_;
        return true;
    }

    void* AllocateAndMapHeaders()
    {
        IMAGE_NT_HEADERS* nt_headers = GetNtHeaders();
        DWORD image_size = nt_headers->OptionalHeader.SizeOfImage;
        void* base = ::VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!base) 
            return nullptr;

        DWORD header_size = nt_headers->OptionalHeader.SizeOfHeaders;
        memcpy(base, pe_content_, header_size);
        return base;
    }

    bool MapSections() 
    {
        IMAGE_NT_HEADERS* nt_headers = GetNtHeaders();
        IMAGE_SECTION_HEADER* section_table = IMAGE_FIRST_SECTION(nt_headers);
        DWORD section_count = nt_headers->FileHeader.NumberOfSections;

        for (DWORD i = 0; i < section_count; ++i) 
        {
            memcpy(
                (BYTE*)base_ + section_table[i].VirtualAddress,
                pe_content_ + section_table[i].PointerToRawData,
                section_table[i].SizeOfRawData);
        }
        return true;
    }

    bool LoadImports() 
    {
        IMAGE_NT_HEADERS* nt_headers = GetNtHeaders();
        IMAGE_DATA_DIRECTORY* import_data_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base_ + import_data_dir->VirtualAddress);

        while (import_descriptor->Name) 
        {
            LPCSTR library_name = (LPCSTR)((BYTE*)base_ + import_descriptor->Name);
            current_imported_library_ = library_name;
            HMODULE library_handle = GetModuleHandleA(library_name);
            if (!library_handle)
                library_handle = ::LoadLibraryA(library_name);

            if (!library_handle) 
            {
                err = err_load_library;
                return false;
            }
            
            if (!ResolveImports(library_handle, import_descriptor))
                return false;

            ++import_descriptor;
        }
        return true;
    }

    bool ResolveImports(
        HMODULE library_handle, 
        IMAGE_IMPORT_DESCRIPTOR* import_descriptor) 
    {
        IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)((BYTE*)base_ + import_descriptor->FirstThunk);
        while (*(DWORD64*)thunk) 
        {
            if (*(DWORD64*)thunk & ((DWORD64)1 << 63)) 
            {  
                // Import by ordinal?
                *(DWORD64*)thunk = (DWORD64)::GetProcAddress(library_handle, (LPCSTR)(*(DWORD64*)thunk & 0xFFFF));
            }
            else 
            {  
                // Import by name
                DWORD64* func_address = (DWORD64*)((BYTE*)base_ + *(DWORD64*)thunk + sizeof(WORD));
                const char* func_name = (LPCSTR)func_address;
                DWORD64 addr = 0;
                if (   ResolveImport_ == nullptr 
                    || !ResolveImport_(ResolveImport_ud_, current_imported_library_, library_handle, func_name, &addr))
                {
                    addr = (DWORD64)::GetProcAddress(library_handle, func_name);
                }
                *(DWORD64*)thunk = addr;
                    
            }
            ++thunk;
        }
        return true;
    }

    void ApplyBaseRelocations() 
    {
        IMAGE_NT_HEADERS* nt_headers = GetNtHeaders();
        DWORD64 base_difference = (DWORD64)base_ - nt_headers->OptionalHeader.ImageBase;
        if (base_difference == 0)
            return;

        IMAGE_DATA_DIRECTORY* relocation_data_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)((BYTE*)base_ + relocation_data_dir->VirtualAddress);

        while (relocation->SizeOfBlock) 
        {
            WORD* reloc = (WORD*)(relocation + 1);
            for (DWORD i = 0, n = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                 i < n; 
                 ++i) 
            {
                if (reloc[i] >> 12 == IMAGE_REL_BASED_DIR64) 
                {
                    DWORD64* patch_addr = (DWORD64*)((BYTE*)base_ + relocation->VirtualAddress + (reloc[i] & 0xFFF));
                    *patch_addr += base_difference;
                }
            }
            relocation = (IMAGE_BASE_RELOCATION*)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }

    void SetSectionProtections()
    {
        IMAGE_NT_HEADERS* nt_headers = GetNtHeaders();
        IMAGE_SECTION_HEADER* section_table = IMAGE_FIRST_SECTION(nt_headers);
        DWORD section_count = nt_headers->FileHeader.NumberOfSections;

        for (DWORD i = 0; i < section_count; ++i)
        {
            DWORD vm_prot = PAGE_NOACCESS;  // Start with no access as default
            auto sec_prot = section_table[i].Characteristics;

            if ((sec_prot & IMAGE_SCN_MEM_EXECUTE) &&
                (sec_prot & IMAGE_SCN_MEM_READ) &&
                (sec_prot & IMAGE_SCN_MEM_WRITE)) {
                vm_prot = PAGE_EXECUTE_READWRITE;
            }
            else if ((sec_prot & IMAGE_SCN_MEM_EXECUTE) &&
                (sec_prot & IMAGE_SCN_MEM_READ)) {
                vm_prot = PAGE_EXECUTE_READ;
            }
            else if (sec_prot & IMAGE_SCN_MEM_EXECUTE) {
                vm_prot = PAGE_EXECUTE;
            }
            else if ((sec_prot & IMAGE_SCN_MEM_READ) &&
                (sec_prot & IMAGE_SCN_MEM_WRITE)) {
                vm_prot = PAGE_READWRITE;
            }
            else if (sec_prot & IMAGE_SCN_MEM_READ) {
                vm_prot = PAGE_READONLY;
            }

            DWORD old_protection;
            ::VirtualProtect(
                (BYTE*)base_ + section_table[i].VirtualAddress, 
                section_table[i].SizeOfRawData, 
                vm_prot, 
                &old_protection);
        }
    }
public:
    enum err_e
    {
        err_none,
        err_open_file,
        err_no_mem,
        err_read,
        err_map_pe,
        err_load_library,
        err_no_entry
    };
    err_e err = err_none;

    void SetResolveImport(ResolveImportProto ResolveImport, void* ud)
    {
        ResolveImport_ = ResolveImport;
        ResolveImport_ud_ = ud;
    }

    explicit PEMapper(BYTE* content, size_t size) : 
        pe_content_(content), pe_size_(size), owns_memory_(false) 
    {
    }

    ~PEMapper() 
    {
        if (base_ != nullptr && owns_memory_)
            ::VirtualFree(base_, 0, MEM_RELEASE);
    }

    static PEMapper* CreateFromFile(const wchar_t* file_path, err_e *perr = nullptr)
    {
        err_e _err = err_none;
        err_e& err = perr ? *perr : _err;

        HANDLE file_handle = ::CreateFileW(
            file_path, 
            GENERIC_READ, 
            0, 
            NULL, 
            OPEN_EXISTING, 
            FILE_ATTRIBUTE_NORMAL, 
            NULL);
        if (file_handle == INVALID_HANDLE_VALUE) 
        {
            err = err_open_file;
            return nullptr;
        }

        DWORD file_size = ::GetFileSize(file_handle, NULL);
        BYTE* buffer = (BYTE*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, file_size);
        if (buffer == nullptr)
        {
            err = err_no_mem;
            ::CloseHandle(file_handle);
            return nullptr;
        }

        DWORD bytes_read;
        bool read_success = ::ReadFile(
            file_handle, 
            buffer, 
            file_size, 
            &bytes_read, 
            NULL);
        ::CloseHandle(file_handle);

        if (!read_success) 
        {
            err = err_read;
            return nullptr;
        }

        PEMapper* mapper = new PEMapper(buffer, file_size);
        mapper->owns_memory_ = true;

        return mapper;
    }

    bool Run() 
    {
        if (!MapPE())
        {
            err = err_map_pe;
            return false;
        }

        using ExeEntry = BOOL(WINAPI*)();
        ExeEntry entry_point = (ExeEntry)entry_point_;
        if (entry_point == nullptr) 
        {
            err = err_no_entry;
            return false;
        }
        return entry_point();
    }
};
