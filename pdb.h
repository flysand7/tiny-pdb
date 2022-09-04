
#pragma once

// VirtualAlloc2 and MapViewOfFile3 required
#pragma comment(lib, "onecore.lib")

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

#if !defined(pdb_assert)
    #include <assert.h>
    #define pdb_assert assert
#endif

#if defined(pdb_single_module)
    #define pdb_func static
#endif

struct pdb_t typedef pdb_t;
struct pdb_t {
    HANDLE file;
    HANDLE mapping;
};

struct pdb_pe_dir_t typedef pdb_pe_dir_t;
struct pdb_pe_dir_t {
    uint32_t rva;
    uint32_t cb;
};

struct pdb_dos_header_t typedef pdb_dos_header_t;
struct pdb_dos_header_t {
    uint16_t magic;
    uint16_t cb_lp;
    uint16_t cp;
    uint16_t cr_lc;
    uint16_t cp_arhdr;
    uint16_t minalloc;
    uint16_t maxalloc;
    uint16_t ss;
    uint16_t sp;
    uint16_t csum;
    uint16_t ip;
    uint16_t cs;
    uint16_t fa_rlc;
    uint16_t ovno;
    uint16_t res[4];
    uint16_t oemid;
    uint16_t oeminfo;
    uint16_t res2[10];
    int32_t  fa_new;
};

struct pdb_pe_header_t typedef pdb_pe_header_t;
struct pdb_pe_header_t {
  uint32_t sig;
  struct {
      uint16_t machine;
      uint16_t csecs;
      uint32_t time;
      uint32_t unused[2];
      uint16_t cbopthdr;
      uint16_t fchrs;
  } filehdr;
  struct {
      // Standard fields
      uint16_t magic;
      uint8_t  lnk_ver[2];
      uint32_t cb_text;
      uint32_t cb_data;
      uint32_t cb_bss;
      uint32_t rva_entry;
      uint32_t rva_code;
      uint32_t rva_data;
      // NT additional fields
      uint32_t rva_base;
      uint32_t cb_sec_align;
      uint32_t cb_file_align;
      uint16_t os_ver[2];
      uint16_t img_ver[2];
      uint16_t subsys_ver[2];
      uint32_t reserved;
      uint32_t cb_image;
      uint32_t cb_hdrs;
      uint32_t checksum;
      uint16_t subsys;
      uint16_t fchrs;
      uint64_t cb_stk_resv;
      uint64_t cb_stk_commit;
      uint64_t cb_heap_resv;
      uint64_t cb_heap_commit;
      uint32_t reserved2;
      uint32_t cdir;
      pdb_pe_dir_t dir[16];
  } opthdr;
};

struct pdb_pe_debug_dir_t typedef pdb_pe_debug_dir_t;
struct pdb_pe_debug_dir_t {
    uint32_t reserved;
    uint32_t time;
    uint16_t ver[2];
    uint32_t type;
    uint32_t cb;
    uint32_t rva;
    uint32_t addr;
};

const char pdb_msf_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\0\0";

struct pdb_msf_header_t typedef pdb_msf_header_t;
struct pdb_msf_header_t {
  char magic[32];
  uint32_t cb_page;
  uint32_t fp_free_map;
  uint32_t cp_file;
  uint32_t cb_dir;
  uint32_t reserved;
  uint32_t fp_dir_index;
};

// DBI header
struct pdb_dbi_header_t typedef pdb_dbi_header_t;
struct pdb_dbi_header_t {
  uint32_t signature;
  uint32_t header;
  uint32_t age;
  uint16_t global_stream_index;
  uint16_t build_index;
  uint16_t public_stream_index;
  uint16_t pdb_dll_version;
  uint16_t sym_record_stream;
  uint16_t pdb_dll_rebuild;
  uint32_t mod_info_size;
  uint32_t section_contrib_size;
  uint32_t section_map_size;
  uint32_t source_info_size;
  uint32_t type_server_size;
  uint32_t mfc_type_server_index;
  uint32_t optional_debug_header_size;
  uint32_t ec_subsystem_size;
  uint16_t flags;
  uint16_t machine;
  uint32_t pad;
};

// Public stream header
struct pdb_ps_header_t typedef pdb_ps_header_t;
struct pdb_ps_header_t {
    uint32_t symHash;
    uint32_t addrMap;
    uint32_t thunkCount;
    uint32_t sizeOfThunk;
    uint16_t isectThunkTable;
    uint16_t padding;
    uint32_t offsetThunkTable;
    uint16_t sectionCount;
    uint16_t padding2;
};

// Header for hash tables
struct pdb_ht_header_t typedef pdb_ht_header_t;
struct pdb_ht_header_t {
    uint32_t signature;
    uint32_t version;
    uint32_t size;
    uint32_t bucketCount;
};

struct pdb_ht_record_t typedef pdb_ht_record_t;
struct pdb_ht_record_t {
    uint32_t offset;
    uint32_t cref;
};

pdb_func char const *pdb_filename_for(size_t pe_size, void const *pe_data);

pdb_func int pdb_fopen(pdb_t *pdb, char const *pdb_filename);

pdb_func int pdb_fclose(pdb_t *pdb);

// ----------------------------------------------------------------------------

#if defined(pdb_implementation)

static void *pdb_read_pages(pdb_t *pdb, uint32_t n, uint32_t *nums) {
    // Find the first free base address that can hold our buffer
    uint32_t cbpages = n*0x1000;
    uint8_t *base = VirtualAlloc2(
        NULL,
        NULL,
        cbpages,
        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
        PAGE_NOACCESS,
        NULL,
        0
    );
    if(base == NULL) {
        return NULL;
    }
    // Map the pages there like a true chad
    for(uint32_t i = 0; i < n; ++i) {
        uint64_t offs_page = ((uint64_t)nums[i])*0x1000;
        if(i != n-1) {
            if(!VirtualFree(base + 0x1000*i, 0x1000, 0x8002)) {
                return NULL;
            }
        }
        void *pages = MapViewOfFile3(
            pdb->mapping,
            NULL,
            base + 0x1000*i,
            offs_page,
            0x1000,
            MEM_REPLACE_PLACEHOLDER,
            PAGE_READONLY,
            NULL,
            0
        );
        if(pages == NULL) {
            return NULL;
        }
    }
    return base;
}

pdb_func char const *pdb_filename_for(size_t pe_size, void const *pe_data) {
    if(pe_size == 0) {
        // hack
        pe_size = (size_t)(-1);
    }
    char const *base = pe_data;
    // Check DOS header and PE headers for magic numbers and sizes
    pdb_dos_header_t const *dos_header = pe_data;
    if(pe_size < sizeof(pdb_dos_header_t)) {
        return NULL;
    }
    if(dos_header->magic != 0x5A4D) {
        return NULL;
    }
    if(dos_header->fa_new + sizeof(pdb_pe_header_t) >= pe_size) {
        return NULL;
    }
    pdb_pe_header_t const *pe_header = (void *)(base + dos_header->fa_new);
    if(pe_header->sig != 0x00004550) {
        return NULL;
    }
    // Verify that we're loading a 64-bit executable
    // (sorry 32-bit fans)
    if(pe_header->filehdr.cbopthdr != sizeof pe_header->opthdr) {
        return NULL;
    }
    // 6th directory entry holds rva and size of .debug directory
    uint32_t debug_dir_rva = pe_header->opthdr.dir[6].rva;
    uint32_t debug_dir_size = pe_header->opthdr.dir[6].cb;
    if(debug_dir_rva == 0) {
        return NULL;
    }
    if(debug_dir_rva + debug_dir_size >= pe_size) {
        return NULL;
    }
    // Get the .debug directory
    pdb_pe_debug_dir_t const *debug_dir = (void *)(base + debug_dir_rva);
    if(debug_dir->type != 2) {
        return NULL;
    }
    if(debug_dir->rva + debug_dir->cb >= pe_size) {
        return NULL;
    }
    // Figure out the size and offset of the debug section
    size_t debug_size = debug_dir->cb;
    char const *debug_base = base + debug_dir->rva;
    // pdb filename would be at offset 24
    char const *pdb_filename = debug_base + 24;
    return pdb_filename;
}

pdb_func int pdb_fopen(pdb_t *pdb, char const *filename) {
    *pdb = (pdb_t){0};
    // Create file and get its size
    pdb->file = CreateFileA(filename, 0x80000000, 0, NULL, 3, 0, NULL);
    if(pdb->file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    LARGE_INTEGER size_struct;
    if(!GetFileSizeEx(pdb->file, &size_struct)) {
        return 0;
    }
    // Create a file mapping for the pdb file
    uint64_t cbpdb = (uint64_t)size_struct.QuadPart;
    uint32_t cbpdbhi = (uint32_t)(cbpdb >> 32);
    uint32_t cbpdblo = (uint32_t)(cbpdb & 0xffffffff);
    pdb->mapping = CreateFileMappingA(
        pdb->file,
        NULL,
        PAGE_READONLY,
        cbpdbhi,
        cbpdblo,
        NULL
    );
    if(pdb->mapping == NULL) {
        return 0;
    }
    // Read and verify msf header
    uint32_t msf_page = 0;
    uint32_t msf_npages = 1;
    pdb_msf_header_t *msf = pdb_read_pages(pdb, msf_npages, &msf_page);
    if(msf == NULL) {
        return 0;
    }
    for(int i = 0; i != 32; ++i) {
        if(msf->magic[i] != pdb_msf_magic[i]) {
            return 0;
        }
    }
    if(msf->cb_page != 0x1000) {
        return 0;
    }
    // Read the stream directory
    uint32_t cpdi = 1;
    uint32_t *di = pdb_read_pages(pdb, cpdi, &msf->fp_dir_index);
    if(di == NULL) {
        return 0;
    }
    uint32_t cpdir = (msf->cb_dir + 0xfff) >> 12;
    uint32_t *dir = pdb_read_pages(pdb, cpdir, di);
    if(dir == NULL) {
        return 0;
    }
    printf("Header: %s\n", (char *)msf);
    return 1;
}

pdb_func int pdb_fclose(pdb_t *pdb) {
    int res = 0;
    if(pdb->mapping != NULL) {
        CloseHandle(pdb->mapping);
        res = 1;
    }
    if(pdb->file != NULL) {
        CloseHandle(pdb->file);
        res = 1;
    }
    return 0;
}

#endif // pdb_implementation
