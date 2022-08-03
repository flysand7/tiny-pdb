
#pragma once

#include <stdint.h>
#include <string.h>

// PDB file format is a special case of the MSF (multi-stream file) format.
// The PDB data is divided into MSF streams, which are not the same thing
// as NTFS streams. The PDB streams are as follows:
// 0      - (reserved)
// 1      - PDB stream, holds basic information, map of stream names to indices
// 2      - TPI stream, holds CodeView type records
// 3      - DBI stream, holds information about modules and section contribs
// 4      - IPI stream, hashed string table
// 5..n+3 - Module streams
// n+4    - Global symbol hash, allows searching global symbols by name
// n+5    - Public symbol hash, allows searching public symbols by addr
// n+6    - Symbol records
// n+7    - Type hash
// The n (number of module streams) can be found in DBI, but also you can
// find the indices of the last 4 streams in DBI header directly.

const char msf_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\0\0";

// This is an MSF header located at offset 0 of the PDB file. The file is
// divided into blocks (usually 4kb), which are also called pages.
// The stream directory holds the sizes and the block arrays of each MSF stream.
// index_page references a starting block of an array of stream directory
// pages.
// free_page_map_page is a block that holds the starting page for a page
// allocation table, which is a bitfield representing which pages are free.
struct msf_header_t typedef msf_header_t;
struct msf_header_t {
  char magic[32];
  uint32_t page_size;
  uint32_t free_page_map_page;
  uint32_t file_npages;
  uint32_t stream_dir_size;
  uint32_t reserved;
  uint32_t index_page;
};

// MSF root (directory) stream holds an array of pages for MSF directory.
// To read a byte one needs to know which page is the offset located on
struct msf_dstr_t typedef msf_dstr_t;
struct msf_dstr_t {
    char     *pdb_base;
    uint32_t  size;
    uint32_t  npages;
    uint32_t *pages;
};

// The representation of MSF stream
struct msf_str_t typedef msf_str_t;
struct msf_str_t {
    char *pdb_base;
    uint32_t size;
    uint32_t npages;
    uint32_t dir_pages_offs;
};

// DBI header
struct dbi_header_t typedef dbi_header_t;
struct dbi_header_t {
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

// Global symbol stream and public symbol stream hold hash records,
// which hold 1-based offsets into sym_rec_stream
struct pdb_ht_record_t typedef pdb_ht_record_t;
struct pdb_ht_record_t {
    uint32_t offset;
    uint32_t cref;
};

// Structure representing PDB file
struct PDB typedef PDB;
struct PDB {
    char *filename;
    char *base;
    size_t file_size;
    msf_dstr_t dir_stream;
    msf_str_t  istreams[5];
    msf_str_t  global_sym_stream;
    msf_str_t  public_sym_stream;
    msf_str_t  sym_rec_stream;
    msf_str_t  type_hash;
};

// Codeview records are stored in symbol record stream
enum pdb_cv_rec_type_t {
    S_END            = 0x0006u,  // block, procedure, "with" or thunk end
    S_FRAMEPROC      = 0x1012u,  // extra frame and proc information
    S_OBJNAME        = 0x1101u,  // full path to the original compiled .obj. can point to remote locations and temporary files, not necessarily the file that was linked into the executable
    S_THUNK32        = 0x1102u,  // thunk start
    S_BLOCK32        = 0x1103u,  // block start
    S_LABEL32        = 0x1105u,  // code label
    S_LDATA32        = 0x110Cu,  // (static) local data
    S_GDATA32        = 0x110Du,  // global data
    S_PUB32          = 0x110Eu,  // public symbol
    S_LPROC32        = 0x110Fu,  // local procedure start
    S_GPROC32        = 0x1110u,  // global procedure start
    S_LTHREAD32      = 0x1112u,  // (static) thread-local data
    S_GTHREAD32      = 0x1113u,  // global thread-local data
    S_PROCREF        = 0x1125u,  // reference to function in any compiland
    S_LPROCREF       = 0x1127u,  // local reference to function in any compiland
    S_TRAMPOLINE     = 0x112Cu,  // incremental linking trampoline
    S_SEPCODE        = 0x1132u,  // separated code (from the compiler)
    S_SECTION        = 0x1136u,  // a COFF section in an executable
    S_COFFGROUP      = 0x1137u,  // original COFF group before it was merged into executable sections by the linker, e.g. .CRT$XCU, .rdata, .bss, .lpp_prepatch_hooks
    S_COMPILE3       = 0x113Cu,  // replacement for S_COMPILE2, more info
    S_ENVBLOCK       = 0x113Du,  // environment block split off from S_COMPILE2
    S_LPROC32_ID     = 0x1146u,  // S_PROC symbol that references ID instead of type
    S_GPROC32_ID     = 0x1147u,  // S_PROC symbol that references ID instead of type
    S_BUILDINFO      = 0x114Cu,  // build info/environment details of a compiland/translation unit
    S_INLINESITE     = 0x114Du,  // inlined function callsite
    S_INLINESITE_END = 0x114Eu,
    S_PROC_ID_END    = 0x114Fu,
    S_LPROC32_DPC    = 0x1155u,
    S_LPROC32_DPC_ID = 0x1156u,
    S_INLINESITE2    = 0x115Du,  // extended inline site information
    S_UDT            = 0x1108u,  // user-defined type
    S_UDT_ST         = 0x1003u,  // user-defined structured types
};

struct pdb_cv_rec_header_t typedef pdb_cv_rec_header_t;
struct pdb_cv_rec_header_t {
    uint16_t size;
    uint16_t kind;
};

// all CodeView records are stored as a header, followed by variable-length data.
// internal Record structs such as S_PUB32, S_GDATA32, etc. correspond to the data layout of a CodeView record of that kind.
struct pdb_cv_record_t typedef pdb_cv_record_t;
struct pdb_cv_record_t {
    pdb_cv_rec_header_t header;
    union {
#pragma pack(push, 1)
        // https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L4069
        struct {
            uint32_t proc_frame_size;
            uint32_t proc_frame_pad;
            uint32_t proc_frame_pad_off;
            uint32_t proc_save_refs_size;
            uint32_t proc_exception_handler_offs;
            uint16_t proc_exception_handler_sec_id;
            struct {
                uint32_t flags_alloca               : 1;
                uint32_t flags_setjmp               : 1;
                uint32_t flags_longjmp              : 1;
                uint32_t flags_inline_asm           : 1;
                uint32_t flags_eh                   : 1;
                uint32_t flags_is_inline            : 1;
                uint32_t flags_seh                  : 1;
                uint32_t flags_naked                : 1;
                uint32_t flags_gs                   : 1;
                uint32_t flags_eh_async             : 1;
                uint32_t flags_gs_no_stack_ordering : 1;
                uint32_t flags_was_inlined          : 1;
                uint32_t flags_gs_check             : 1;
                uint32_t flags_save_buffers         : 1;
                uint32_t flags_encoded_local_bp     : 2;
                uint32_t flags_encoded_params_bp    : 2;
                uint32_t flags_pogo                 : 1;
                uint32_t flags_pogo_valid_counts    : 1;
                uint32_t flags_opt_speed            : 1;
                uint32_t flags_cfg                  : 1;
                uint32_t flags_cfw                  : 1;
                uint32_t flags_pad                  : 9;
            } flags;
        } frame_proc;
        // https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L3696
        struct {
            uint32_t flags;
            uint32_t offset;
            uint16_t section;
            char name[];
        } pub32;
        struct {
            uint32_t typeIndex;
            uint32_t offset;
            uint16_t section;
            char name[];
        } gdata32, gthread32, ldata32, lthread32;
        struct {
            uint32_t signature;
            char name[];
        } S_OBJNAME;
        struct {
            uint16_t type;
            uint16_t size;
            uint32_t thunkOffset;
            uint32_t targetOffset;
            uint16_t thunkSection;
            uint16_t targetSection;
        } S_TRAMPOLINE;
        struct {
            uint16_t sectionNumber;
            uint8_t alignment;
            uint32_t rva;
            uint32_t length;
            uint32_t characteristics;
            char name[];
        } S_SECTION;

        struct {
            uint32_t size;
            uint32_t characteristics;
            uint32_t offset;
            uint16_t section;
            char name[];
        } S_COFFGROUP;

        struct {
            uint32_t parent;
            uint32_t end;
            uint32_t next;
            uint32_t offset;
            uint16_t section;
            uint16_t length;
            uint8_t  thunk;
            char name[];
        } S_THUNK32;

        struct {
            uint32_t parent;
            uint32_t end;
            uint32_t next;
            uint32_t codeSize;
            uint32_t debugStart;
            uint32_t debugEnd;
            uint32_t typeIndex;
            uint32_t offset;
            uint16_t section;
            uint8_t  flags;
            char name[];
        } S_LPROC32, S_GPROC32, S_LPROC32_ID, S_GPROC32_ID, S_LPROC32_DPC, S_LPROC32_DPC_ID;

        struct {
            uint32_t parent;
            uint32_t end;
            uint32_t codeSize;
            uint32_t offset;
            uint16_t section;
            char name[];
        } S_BLOCK32;

        struct {
            uint32_t offset;
            uint16_t section;
            uint8_t  flags;
            char name[];
        } S_LABEL32;

        struct {
            uint32_t typeIndex;    // refers to a type index in the IPI stream
        } S_BUILDINFO;

        struct {
            uint32_t flags;
            uint16_t machine;
            uint16_t versionFrontendMajor;
            uint16_t versionFrontendMinor;
            uint16_t versionFrontendBuild;
            uint16_t versionFrontendQFE;
            uint16_t versionBackendMajor;
            uint16_t versionBackendMinor;
            uint16_t versionBackendBuild;
            uint16_t versionBackendQFE;
            char version[];
        } S_COMPILE3;

        // https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L3372
        struct {
            uint8_t flags;
            char strings[];
        } S_ENVBLOCK;

        struct {
            unsigned long typind;
            char name[];
        } S_UDT, S_UDT_ST;
#pragma pack(pop)
    } data;
};

// Load PDB for a given loaded module (.exe or .dll file)
// if mod_path is NULL loads PDB for the current executable
// returns 1 if pdb was loaded successfully, 0 otherwise
int pdb_module_load(PDB *pdb, void *mod_path);

// Read N bytes from MSF directory stream at offset offs into a buffer buf.
int msf_dread(PDB *pdb, uint32_t offs, uint32_t N, void *buf);

// Read N bytes from MSF stream at offset offs into a buffer pointed to by p
int msf_sread(PDB *pdb, msf_str_t *stream, uint32_t offs, uint32_t N, void *p);

// Free loaded PDB
void pdb_free(PDB *pdb);

// ---------------------------------------------------------------------------

#if defined(pdb_implementation)

// For test, TODO remove later
#include <stdlib.h>
#include <assert.h>

struct data_dir_t typedef data_dir_t;
struct data_dir_t{
    uint32_t rva;
    uint32_t size;
};
struct pe_file_header_t typedef pe_file_header_t;
struct pe_file_header_t {
    uint16_t machine;
    uint16_t num_secs;
    uint32_t timestamp;
    uint32_t syms_ptr;
    uint32_t nsyms;
    uint16_t opt_hdr_size;
    uint16_t characteristics;
};

struct pe_header_t typedef pe_header_t;
struct pe_header_t {
  uint32_t signature;
  pe_file_header_t image_header;
  struct {
      uint16_t   magic;
      uint16_t   linker_version;
      uint32_t   code_size;
      uint32_t   bss_size;
      uint32_t   data_size;
      uint32_t   entry_rva;
      uint32_t   code_base;
      uint32_t   data_base;
      uint32_t   base_rva;
      uint32_t   section_align;
      uint32_t   file_align;
      uint32_t   os_version;
      uint32_t   image_version;
      uint32_t   sys_version;
      uint32_t   win32_version;
      uint32_t   image_size;
      uint32_t   headers_size;
      uint32_t   checksum;
      uint16_t   sumsystem;
      uint16_t   dll;
      uint64_t   stack_reserve_size;
      uint64_t   stack_commit_size;
      uint64_t   heap_reserve_size;
      uint64_t   heap_commit_size;
      uint32_t   loader_flags;
      uint32_t   dir_entries_size;
      data_dir_t dir_entries[16];
  } optional_header;
};

struct debug_dir_t typedef debug_dir_t;
struct debug_dir_t {
    uint32_t reserved;
    uint32_t timestamp;
    uint32_t version;
    uint32_t type;
    uint32_t data_size;
    uint32_t data_rva;
    uint32_t data_addr;
};

static void *msf_page(void *pdb_base, uint32_t n) {
    return pdb_base + n*0x1000;
}

static inline uint32_t msf_npages(uint32_t size) {
    return (size+0xfff)>>12;
}

static inline uint32_t msf_pagenum(uint32_t offs) {
    return offs >> 12;
}

static inline uint32_t msf_pageoffs(uint32_t offs) {
    return offs & 0xfff;
}

static void *pdb_slurp(char *filename, size_t *out_file_size) {
    FILE *fp = fopen(filename, "rb");
    if(fp == NULL) {
        return NULL;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        return NULL;
    }
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *file_buf = _aligned_malloc(file_size, 0x100000000);
    if(!file_buf) {
        return NULL;
    }
    if(!fread(file_buf, 1, file_size, fp)) {
        return NULL;
    }
    *out_file_size = file_size;
    return file_buf;
}

int msf_dread(PDB *pdb, uint32_t offs, uint32_t nbytes, void *p) {
    msf_dstr_t *dir = &pdb->dir_stream;
    uint8_t *buf = p;
    uint32_t offs_page = msf_pagenum(offs);
    uint32_t offs_start = msf_pageoffs(offs);
    uint32_t nread = 0;
    while(nread != nbytes) {
        if(offs_page >= dir->npages) {
            return 0;
        }
        uint32_t dir_page = dir->pages[offs_page];
        uint8_t *page = msf_page(dir->pdb_base, dir_page);
        uint32_t i = offs_start;
        while(nread != nbytes && i != 0x1000) {
            buf[nread] = page[i];
            ++nread;
            ++i;
        }
        offs_start = 0;
    }
    return 1;
}

int msf_sread(PDB *pdb, msf_str_t *stream, uint32_t offs, uint32_t nbytes, void *p) {
    uint8_t *buf = p;
    uint32_t offs_page = msf_pagenum(offs);
    uint32_t offs_start = msf_pageoffs(offs);
    uint32_t nread = 0;
    while(nread != nbytes) {
        if(offs_page >= stream->npages) {
            return 0;
        }
        uint32_t stream_page;
        if(!msf_dread(pdb, stream->dir_pages_offs + 4*offs_page, 4, &stream_page)) {
            return 0;
        }
        uint8_t *page = msf_page(pdb->base, stream_page);
        uint32_t i = offs_start;
        while(nread != nbytes && i != 0x1000) {
            buf[nread] = page[i];
            ++nread;
            ++i;
        }
        offs_start = 0;
        offs_page += 1;
    }
    return 1;
}

int pdb_module_load(PDB *pdb, void *image) {
    // Find and verify the PE header. Module handle is secretly a pointer to
    // the base of the loaded PE file, and offset to the PE header is stored at
    // offset 60h from the start of the file.
    char *image_base = image;
    uint32_t pe_offset = *(uint32_t *)&image_base[60];
    pe_header_t *pe_header = (void *)&image_base[pe_offset];
    if(pe_header->signature != 0x00004550) {
        return 0;
    }
    // Find and verify .pdata directory. that would be 6'th directory
    // .pdata directory must have type 2 (codeview data)
    uint32_t pdata_rva = pe_header->optional_header.dir_entries[6].rva;
    if(pdata_rva == 0) {
        return 0;
    }
    debug_dir_t *debug_dir = (void *)&image_base[pdata_rva];
    if(debug_dir->type != 2) {
        return 0;
    }
    // Figure out the size and offset of the data section
    size_t debug_section_size = debug_dir->data_size;
    char *debug_section = image_base + debug_dir->data_rva;
    // pdb filename would be at offset 24
    char *pdb_filename = debug_section + 24;
    pdb->filename = pdb_filename;
    // Slurp pdb file into memory
    pdb->base = pdb_slurp(pdb_filename, &pdb->file_size);
    if(pdb->base == NULL) {
        return 0;
    }
    // Verify that PDB file is indeed an MSF file
    msf_header_t *msf = (void *)pdb->base;
    for(int i = 0; i != 32; ++i) {
        if(msf->magic[i] != msf_magic[i]) {
            return 0;
        }
    }
    // Only support PDB's with block size of 4K
    if(msf->page_size != 0x1000) {
        return 0;
    }
    // Make a stream for MSF directory stream
    msf_dstr_t dir_stream;
    dir_stream.pdb_base = pdb->base;
    dir_stream.size = msf->stream_dir_size;
    dir_stream.npages = msf_npages(msf->stream_dir_size);
    dir_stream.pages = msf_page(pdb->base, msf->index_page);
    pdb->dir_stream = dir_stream;
    // Get the number of streams from msf directory
    uint32_t nstreams;
    if(!msf_dread(pdb, 0, 4, &nstreams)) {
        return 0;
    }
    // Get the sizes of the first 5 streams
    uint32_t istream_sizes[5];
    if(!msf_dread(pdb, 4, 5*sizeof(uint32_t), &istream_sizes)) {
        return 0;
    }
    // Read in the first 4 streams into PDB file (stream 0 ignored)
    uint32_t pages_offs = 4+4*nstreams;
    uint32_t cur_pages_offs = pages_offs;
    for(int i = 0; i < 5; ++i) {
        msf_str_t *stream = &pdb->istreams[i];
        stream->pdb_base = pdb->base;
        stream->dir_pages_offs = cur_pages_offs;
        stream->size = istream_sizes[i];
        stream->npages = msf_npages(istream_sizes[i]);
        cur_pages_offs += 4*stream->npages;
    }
    // Try reading DBI buffer
    dbi_header_t dbi;
    if(!msf_sread(pdb, &pdb->istreams[3], 0, sizeof dbi, &dbi)) {
        return 0;
    }
    if(dbi.signature != 0xffffffff) {
        return 0;
    }
    if(dbi.machine != 0x8664) {
        return 0;
    }
    // Continue reading streams until we find the streams that are of interest
    int public_symbol_stream_found = 0;
    int global_symbol_stream_found = 0;
    int sym_rec_stream_found = 0;
    for(int i = 5; i < nstreams; ++i) {
        uint32_t stream_size;
        if(!msf_dread(pdb, 4+i*sizeof(uint32_t), 4, &stream_size)) {
            return 0;
        }
        uint32_t stream_pages = msf_npages(stream_size);
        msf_str_t *stream = NULL;
        if(i == dbi.global_stream_index) {
            stream = &pdb->global_sym_stream;
            global_symbol_stream_found = 1;
        }
        else if(i == dbi.public_stream_index) {
            stream = &pdb->public_sym_stream;
            public_symbol_stream_found = 1;
        }
        else if(i == dbi.sym_record_stream) {
            stream = &pdb->sym_rec_stream;
            sym_rec_stream_found = 1;
        }
        if(stream != NULL) {
            stream->pdb_base = pdb->base;
            stream->dir_pages_offs = cur_pages_offs;
            stream->size = stream_size;
            stream->npages = stream_pages;
        }
        cur_pages_offs += 4*stream_pages;
    }
    if(!public_symbol_stream_found || !global_symbol_stream_found || !sym_rec_stream_found) {
        return 0;
    }
    // Read symbol records from public symbol stream
    pdb_ht_record_t some_recs[1024];
    uint32_t ht_offs = sizeof(pdb_ps_header_t) + sizeof(pdb_ht_header_t);
    if(!msf_sread(pdb, &pdb->public_sym_stream, ht_offs, sizeof some_recs, &some_recs)) {
        assert(0);
    }
    // Find each hash record in the symbol record stream and print the name
    printf("symbols found:\n");
    for(int i = 0; i != 1024; ++i) {
        pdb_ht_record_t *hash_record = &some_recs[i];
        uint32_t offs = hash_record->offset - 1;
        pdb_cv_record_t sym;
        if(!msf_sread(pdb, &pdb->sym_rec_stream, offs, sizeof sym, &sym)) {
            assert(0);
        }
        if(sym.header.kind != S_PUB32) {
            assert(0);
        }
        char *name = sym.data.pub32.name;
        if(name[0] != '_' && name[0] != '?') {
            printf("  %s\n", name);
        }
    }
    // -----------------------------------------------------------------------
    // Read some symbols from symbol record stream
    // uint8_t pages[0x1000 * 128];
    // if(!msf_sread(pdb, &pdb->sym_rec_stream, 0, sizeof pages, &pages)) {
    //     assert(0);
    // }
    // pdb_cv_record_t *sym = (void *)pages;
    // while((uint8_t *)sym < pages + sizeof pages) {
    //     if(sym->header.kind == S_PUB32) {
    //         char *name = sym->data.pub32.name;
    //         uint32_t rec_offset = (unsigned)((uint8_t*)sym - (uint8_t*)&pages);
    //         printf("0x%.8x: %s\n", rec_offset, name);
    //     }
    //     // size holds size of the symbol except for the size field, thus
    //     // we advance by full size, or size+2
    //     uint32_t size = sym->header.size;
    //     sym = (void *)&((uint8_t*)sym)[size+2];
    // }
    return 1;
}

void pdb_free(PDB *pdb) {
    //
}

#endif // pdb_implementation
