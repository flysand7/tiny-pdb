
#pragma once

#include <stdint.h>

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

const char msf_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\0\0";

// This is an MSF header located at offset 0 of the PDB file. The file is
// divided into blocks (usually 4kb), which are also called pages.
// The stream directory holds the sizes and the block arrays of each MSF stream.
// index_page references a starting block of an array of stream directory
// pages.
struct msf_header_t typedef msf_header_t;
struct msf_header_t {
  char magic[32];
  uint32_t page_size;
  uint32_t free_page_map_pages;
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

// Load PDB for a given loaded module (.exe or .dll file)
// if mod_path is NULL loads PDB for the current executable
// returns 1 if pdb was loaded successfully, 0 otherwise
int  pdb_module_load(PDB *pdb, void *mod_path);

// Read N bytes from MSF directory stream at offset offs into a buffer buf.
int  msf_dread(PDB *pdb, uint32_t offs, uint32_t N, void *buf);

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
    uint32_t nread;
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
    return 1;
}

void pdb_free(PDB *pdb) {
    //
}

#endif // pdb_implementation
