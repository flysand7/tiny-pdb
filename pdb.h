
#pragma once

#include <stdint.h>
#include <stdbool.h>

#if defined(pdb_single_module)
    #define pdb_func static
#endif

#if !defined(pdb_assert)
    #include <assert.h>
    #define pdb_assert assert
#endif

#if !defined(pdb_string)
    #include <string.h>
    #define pdb_strcmp strcmp
    #define pdb_memcpy memcpy
#endif

#if !defined(pdb_stdlib)
    #include <stdlib.h>
    #define pdb_malloc malloc
    #define pdb_realloc realloc
    #define pdb_free free
#endif

// Status codes
#define PDB_OK 0
#define PDB_BAD_FORMAT 1
#define PDB_UNSUPPORTED 2

// API Types
typedef struct pdb_t pdb_t;
typedef struct pdb_stream_t pdb_stream_t;
typedef struct pdb_hash_table_entry_t pdb_hash_table_entry_t;
typedef struct pdb_hash_table_t pdb_hash_table_t;
typedef struct pdb_hash_table_entry_t pdb_hash_table_entry_t;
typedef struct pdb_type_array_t pdb_type_array_t;

struct pdb_stream_t {
    uint32_t cb_size;
    uint32_t cp_size;
    uint32_t *pages;
};

struct pdb_hash_table_entry_t {
    union {
        struct {
            uint32_t stream_name;
            uint32_t stream_index;
        };
        struct {
            uint32_t k;
            uint32_t v;
        };
    };
};

struct pdb_hash_table_t {
    uint32_t string_buf_size;
    char *string_buf;
    uint32_t size;
    uint32_t cap;
    uint32_t cw_bits_present;
    uint32_t *bits_present;
    uint32_t cw_bits_deleted;
    uint32_t *bits_deleted;
    pdb_hash_table_entry_t *entries;
};

struct pdb_type_array_t {
    uint32_t cap;
    uint32_t len;
    void **types;
};

struct pdb_t {
    // Raw data
    size_t size;
    void *data;
    // Metadata
    uint32_t cp_file;
    uint32_t is_fastlink;
    uint32_t is_incremental;
    uint32_t has_private_symbols;
    uint32_t has_conflicting_types;
    // Streams
    uint32_t nstreams;
    pdb_stream_t *streams;
    pdb_stream_t names_stream;
    // Hash table
    pdb_hash_table_t named_stream_map;
    // Types
    pdb_type_array_t tpi_types;
    pdb_type_array_t ipi_types;
};

pdb_func char const *pdb_filename_for_module(size_t size, void const *module);

pdb_func int pdb_read(pdb_t *pdb, size_t buf_size, void *buf);

// ----------------------------------------------------------------------------

#if defined(pdb_implementation)

typedef struct pdb_pdb_stream_t pdb_pdb_stream_t;
typedef struct pdb_hash_table_t pdb_hash_table_t;

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

typedef struct pdb_tpi_stream_header_t pdb_tpi_stream_header_t;
struct pdb_tpi_stream_header_t {
    uint32_t version;
    uint32_t size;
    uint32_t ti_begin;
    uint32_t ti_end;
    uint32_t tr_bytes;
    uint16_t hash_stream_index;
    uint16_t hash_aux_stream_index;
    uint32_t hash_key_size;
    uint32_t num_hash_buckets;
    int32_t hash_value_buffer_offset;
    uint32_t hash_value_buffer_len;
    int32_t index_offset_buffer_offset;
    uint32_t index_offset_buffer_len;
    int32_t hash_adj_buffer_offset;
    uint32_t hash_adj_buffer_len;
};

#pragma pack(push, 1)
typedef struct {
    unsigned long ptrtype     :5; // ordinal specifying pointer type (CV_ptrtype_e)
    unsigned long ptrmode     :3; // ordinal specifying pointer mode (CV_ptrmode_e)
    unsigned long isflat32    :1; // true if 0:32 pointer
    unsigned long isvolatile  :1; // TRUE if volatile pointer
    unsigned long isconst     :1; // TRUE if const pointer
    unsigned long isunaligned :1; // TRUE if unaligned pointer
    unsigned long isrestrict  :1; // TRUE if restricted pointer (allow agressive opts)
    unsigned long size        :6; // size of pointer (in bytes)
    unsigned long ismocom     :1; // TRUE if it is a MoCOM pointer (^ or %)
    unsigned long islref      :1; // TRUE if it is this pointer of member function with & ref-qualifier
    unsigned long isrref      :1; // TRUE if it is this pointer of member function with && ref-qualifier
    unsigned long unused      :10;// pad out to 32-bits for following cv_typ_t's
} pdb_cv_lf_pointer_attr;

typedef struct {
    uint16_t len;
    uint16_t leaf;  // LF_POINTER
    uint32_t utype; // type index of the underlying type
    pdb_cv_lf_pointer_attr attr;
    union {
        struct {
            uint32_t pmclass;    // index of containing class for pointer to member
            uint16_t pmenum;     // enumeration specifying pm format (CV_pmtype_e)
        } pm;
    } pbase;
} pdb_cv_lf_pointer;

typedef struct {
    uint16_t packed        :1; // true if structure is packed
    uint16_t ctor          :1; // true if constructors or destructors present
    uint16_t ovlops        :1; // true if overloaded operators present
    uint16_t isnested      :1; // true if this is a nested class
    uint16_t cnested       :1; // true if this class contains nested types
    uint16_t opassign      :1; // true if overloaded assignment (=)
    uint16_t opcast        :1; // true if casting methods
    uint16_t fwdref        :1; // true if forward reference (incomplete defn)
    uint16_t scoped        :1; // scoped definition
    uint16_t hasuniquename :1; // true if there is a decorated name following the regular name
    uint16_t sealed        :1; // true if class cannot be used as a base class
    uint16_t hfa           :2; // CV_HFA_e
    uint16_t intrinsic     :1; // true if class is an intrinsic type (e.g. __m128d)
    uint16_t mocom         :2; // CV_MOCOM_UDT_e
} pdb_cv_prop;

typedef struct {
    uint16_t access      :2; // access protection CV_access_t
    uint16_t mprop       :3; // method properties CV_methodprop_t
    uint16_t pseudo      :1; // compiler generated fcn and does not exist
    uint16_t noinherit   :1; // true if class cannot be inherited
    uint16_t noconstruct :1; // true if class cannot be constructed
    uint16_t compgenx    :1; // compiler generated fcn and does exist
    uint16_t sealed      :1; // true if method cannot be overridden
    uint16_t unused      :6; // unused
} pdb_cv_field_attr;

typedef struct {
    uint16_t len;
    uint16_t leaf; // LF_FIELDLIST
} pdb_cv_lf_field_list;

typedef struct {
    uint16_t leaf; // LF_LONG
    int32_t val;   // signed 32-bit value
} pdb_cv_lf_long;

typedef struct {
    uint16_t leaf; // LF_QUAD
    int64_t val;   // signed 64-bit value
} pdb_cv_lf_quad;

typedef struct {
    uint16_t leaf; // LF_VARSTRING
    uint8_t val[];
} pdb_cv_lf_varstring;

typedef struct {
    uint16_t       leaf;  // LF_MEMBER
    pdb_cv_field_attr attr;  // attribute mask
    uint32_t       index; // index of type record for field
    // variable length offset of field followed
    // by length prefixed name of field
    uint8_t offset[];
} CV_LFMember;

typedef struct pdb_cv_lf_struct {
    uint16_t len;
    uint16_t leaf;    // LF_CLASS, LF_STRUCT, LF_INTERFACE
    uint16_t count;   // count of number of elements in class
    pdb_cv_prop  property;// property attribute field (prop_t)
    uint32_t field;   // type index of LF_FIELD descriptor list
    uint32_t derived; // type index of derived from list if not zero
    uint32_t vshape;  // type index of vshape table for this class
    uint8_t  data[];  // data describing length of structure in bytes and name
} pdb_cv_lf_struct;

typedef enum {
    CV_LOCAL_IS_PARAM         = 1,   // variable is a parameter
    CV_LOCAL_IS_ADDR_TAKEN    = 2,   // address is taken
    CV_LOCAL_IS_COMPILER_GEND = 4,   // variable is compiler generated
    CV_LOCAL_IS_AGGREGATE     = 8,   // the symbol is splitted in temporaries, which are treated by compiler as independent entities
    CV_LOCAL_IS_AGGREGATED    = 16,  // Counterpart of fIsAggregate - tells that it is a part of a fIsAggregate symbol
    CV_LOCAL_IS_ALIASED       = 32,  // variable has multiple simultaneous lifetimes
    CV_LOCAL_IS_ALIAS         = 64,  // represents one of the multiple simultaneous lifetimes
    CV_LOCAL_IS_RETURN_VALUE  = 128, // represents a function return value
    CV_LOCAL_IS_OPTIMIZED_OUT = 256, // variable has no lifetimes
    CV_LOCAL_IS_ENREG_GLOBAL  = 512, // variable is an enregistered global
    CV_LOCAL_IS_ENREG_STATIC  = 1024,// variable is an enregistered static
} pdb_cv_local_var_flags;

// pdb_cv_local is followed by CV_DefRange memory
typedef struct {
    uint16_t reclen; // Record length
    uint16_t rectyp; // S_LOCAL
    uint32_t typind; // type index
    uint16_t flags;  // local var flags (pdb_cv_local_var_flags)
    uint8_t  name[]; // Name of this symbol, a null terminated array of UTF8 characters.
} pdb_cv_local;

typedef struct {
    uint32_t offset_start;
    uint16_t isect_start;
    uint16_t cb_range;
} pdb_cv_address_range;

// Represents the holes in overall address range, all address is pre-bbt.
// it is for compress and reduce the amount of relocations need.
typedef struct {
    uint16_t gap_start_offset; // relative offset from the beginning of the live range.
    uint16_t cb_range;         // length of this gap.
} pdb_cv_address_gap;

// A live range of sub field of variable
typedef struct {
    uint16_t reclen;       // Record length
    uint16_t rectyp;       // S_DEFRANGE
    uint32_t program;      // DIA program to evaluate the value of the symbol
    pdb_cv_address_range range; // Range of addresses where this program is valid
    pdb_cv_address_gap gaps[];  // The value is not available in following gaps
} pdb_cv_def_range;

typedef struct {
    uint16_t reclen;       // Record length
    uint16_t rectyp;       // S_DEFRANGE_FRAMEPOINTER_REL
    int32_t local;
    pdb_cv_address_range range; // Range of addresses where this program is valid
    pdb_cv_address_gap gaps[];  // The value is not available in following gaps
} pdv_cv_def_range_frame_rel;

typedef struct {
    uint16_t reclen; // Record length
    uint16_t rectyp; // S_REGREL32
    uint32_t off;    // offset of symbol
    uint32_t typind; // Type index or metadata token
    uint16_t reg;    // register index for symbol
    uint8_t  name[]; // Length-prefixed name
} pdb_cv_reg_rel32;
#pragma pack(pop)

// represents a CodeView type entry, they start with 16bits for length field
typedef struct pdb_cv_type_entry {
    uint32_t key;   // points to somewhere in the debug$T section, 0 is assumed to mean nothing
    uint16_t value; // type index
} pdb_cv_type_entry;

enum {
    COFF_MACHINE_AMD64 = 0x8664, // AMD64 (K8)
    COFF_MACHINE_ARM64 = 0xAA64, // ARM64 Little-Endian
};

enum {
    S_LDATA32        = 0x110c, // Module-local symbol
    S_GDATA32        = 0x110d, // Global data symbol
    S_LPROC32_ID     = 0x1146,
    S_GPROC32_ID     = 0x1147,
    S_INLINESITE     = 0x114d, // inlined function callsite.
    S_INLINESITE_END = 0x114e,
    S_PROC_ID_END    = 0x114f,
    S_FRAMEPROC      = 0x1012, // extra frame and proc information
    S_REGREL32       = 0x1111, // register relative address
    S_LOCAL          = 0x113e, // defines a local symbol in optimized code
    S_DEFRANGE       = 0x113f, // defines a single range of addresses in which symbol can be evaluated
    S_DEFRANGE_FRAMEPOINTER_REL = 0x1142, // range for stack symbol.
};

enum {
    T_VOID          = 0x0003,   // void
    T_BOOL08        = 0x0030,   // 8 bit boolean
    T_CHAR          = 0x0010,   // 8 bit signed
    T_UCHAR         = 0x0020,   // 8 bit unsigned
    T_INT1          = 0x0068,   // 8 bit signed int
    T_UINT1         = 0x0069,   // 8 bit unsigned int
    T_INT2          = 0x0072,   // 16 bit signed int
    T_UINT2         = 0x0073,   // 16 bit unsigned int
    T_INT4          = 0x0074,   // 32 bit signed int
    T_UINT4         = 0x0075,   // 32 bit unsigned int
    T_INT8          = 0x0076,   // 64 bit signed int
    T_UINT8         = 0x0077,   // 64 bit unsigned int
    T_REAL32        = 0x0040,   // 32 bit real
    T_REAL64        = 0x0041,   // 64 bit real
};

enum {
    LF_NUMERIC          = 0x8000,
    LF_CHAR             = 0x8000,
    LF_SHORT            = 0x8001,
    LF_USHORT           = 0x8002,
    LF_LONG             = 0x8003,
    LF_ULONG            = 0x8004,
    LF_REAL32           = 0x8005,
    LF_REAL64           = 0x8006,
    LF_REAL80           = 0x8007,
    LF_REAL128          = 0x8008,
    LF_QUADWORD         = 0x8009,
    LF_UQUADWORD        = 0x800a,
    LF_REAL48           = 0x800b,
    LF_COMPLEX32        = 0x800c,
    LF_COMPLEX64        = 0x800d,
    LF_COMPLEX80        = 0x800e,
    LF_COMPLEX128       = 0x800f,
    LF_VARSTRING        = 0x8010,

    LF_POINTER          = 0x1002,
    LF_PROCEDURE        = 0x1008,
    LF_ARGLIST          = 0x1201,
    LF_FIELDLIST        = 0x1203,
    LF_ARRAY            = 0x1503,
    LF_CLASS            = 0x1504,
    LF_STRUCTURE        = 0x1505,
    LF_UNION            = 0x1506,
    LF_ENUM             = 0x1507,
    LF_MEMBER           = 0x150d,
    LF_FUNC_ID          = 0x1601,

    LF_STRING           = 0x0082,

    // the idea is that if you need to pad a
    // type you fill in the remaining space with a
    // sequence of LF_PADs like this
    //
    // Your record's bytes:
    //   DATA LF_PAD2 LF_PAD1 LF_PAD0
    LF_PAD0             = 0x00f0,
};

enum {
  PDB_TYPE_NONE = 0x0000,              // uncharacterized type (no type)
  PDB_TYPE_VOID = 0x0003,              // void
  PDB_TYPE_NOTTRANSLATED = 0x0007,     // type not translated by cvpack
  PDB_TYPE_HRESULT = 0x0008,           // OLE/COM HRESULT
  PDB_TYPE_SIGNEDCHARACTER = 0x0010,   // 8 bit signed
  PDB_TYPE_UNSIGNEDCHARACTER = 0x0020, // 8 bit unsigned
  PDB_TYPE_NARROWCHARACTER = 0x0070,   // really a char
  PDB_TYPE_WIDECHARACTER = 0x0071,     // wide char
  PDB_TYPE_CHARACTER16 = 0x007a,       // char16_t
  PDB_TYPE_CHARACTER32 = 0x007b,       // char32_t
  PDB_TYPE_CHARACTER8 = 0x007c,        // char8_t
  PDB_TYPE_SBYTE = 0x0068,       // 8 bit signed int
  PDB_TYPE_BYTE = 0x0069,        // 8 bit unsigned int
  PDB_TYPE_INT16SHORT = 0x0011,  // 16 bit signed
  PDB_TYPE_UINT16SHORT = 0x0021, // 16 bit unsigned
  PDB_TYPE_INT16 = 0x0072,       // 16 bit signed int
  PDB_TYPE_UINT16 = 0x0073,      // 16 bit unsigned int
  PDB_TYPE_INT32LONG = 0x0012,   // 32 bit signed
  PDB_TYPE_UINT32LONG = 0x0022,  // 32 bit unsigned
  PDB_TYPE_INT32 = 0x0074,       // 32 bit signed int
  PDB_TYPE_UINT32 = 0x0075,      // 32 bit unsigned int
  PDB_TYPE_INT64QUAD = 0x0013,   // 64 bit signed
  PDB_TYPE_UINT64QUAD = 0x0023,  // 64 bit unsigned
  PDB_TYPE_INT64 = 0x0076,       // 64 bit signed int
  PDB_TYPE_UINT64 = 0x0077,      // 64 bit unsigned int
  PDB_TYPE_INT128OCT = 0x0014,   // 128 bit signed int
  PDB_TYPE_UINT128OCT = 0x0024,  // 128 bit unsigned int
  PDB_TYPE_INT128 = 0x0078,      // 128 bit signed int
  PDB_TYPE_UINT128 = 0x0079,     // 128 bit unsigned int
  PDB_TYPE_FLOAT16 = 0x0046,                 // 16 bit real
  PDB_TYPE_FLOAT32 = 0x0040,                 // 32 bit real
  PDB_TYPE_FLOAT32PARTIALPRECISION = 0x0045, // 32 bit PP real
  PDB_TYPE_FLOAT48 = 0x0044,                 // 48 bit real
  PDB_TYPE_FLOAT64 = 0x0041,                 // 64 bit real
  PDB_TYPE_FLOAT80 = 0x0042,                 // 80 bit real
  PDB_TYPE_FLOAT128 = 0x0043,                // 128 bit real
  PDB_TYPE_COMPLEX16 = 0x0056,                 // 16 bit complex
  PDB_TYPE_COMPLEX32 = 0x0050,                 // 32 bit complex
  PDB_TYPE_COMPLEX32PARTIALPRECISION = 0x0055, // 32 bit PP complex
  PDB_TYPE_COMPLEX48 = 0x0054,                 // 48 bit complex
  PDB_TYPE_COMPLEX64 = 0x0051,                 // 64 bit complex
  PDB_TYPE_COMPLEX80 = 0x0052,                 // 80 bit complex
  PDB_TYPE_COMPLEX128 = 0x0053,                // 128 bit complex
  PDB_TYPE_BOOLEAN8 = 0x0030,   // 8 bit boolean
  PDB_TYPE_BOOLEAN16 = 0x0031,  // 16 bit boolean
  PDB_TYPE_BOOLEAN32 = 0x0032,  // 32 bit boolean
  PDB_TYPE_BOOLEAN64 = 0x0033,  // 64 bit boolean
  PDB_TYPE_BOOLEAN128 = 0x0034, // 128 bit boolean
};

enum uint32_t {
  PDB_TYPE_MODE_DIRECT = 0,         // Not a pointer
  PDB_TYPE_MODE_NEAR_POINTER = 1,   // Near pointer
  PDB_TYPE_MODE_FAR_POINTER = 2,    // Far pointer
  PDB_TYPE_MODE_HUGE_POINTER = 3,   // Huge pointer
  PDB_TYPE_MODE_NEAR_POINTER32 = 4, // 32 bit near pointer
  PDB_TYPE_MODE_FAR_POINTER32 = 5,  // 32 bit far pointer
  PDB_TYPE_MODE_NEAR_POINTER64 = 6, // 64 bit near pointer
  PDB_TYPE_MODE_NEAR_POINTER128 = 7 // 128 bit near pointer
};


static const char pdb_msf_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\0\0";

#define PDB_PAGE_SIZE 0x1000
#define PDB_DOS_MAGIC 0x5A4D
#define PDB_PE_MAGIC  0x00004550

static inline uint32_t pdb_ceildiv(uint32_t a, uint32_t b) {
    return (a+b-1) / b;
}

static void *pdb_read_pages(pdb_t *pdb, uint32_t n, uint32_t *pages) {
    void *buffer = pdb_malloc(n * PDB_PAGE_SIZE);
    for(uint32_t i = 0; i != n; ++i) {
        uint32_t page = pages[i];
        if(page > pdb->cp_file) {
            return NULL;
        }
        void *src = (uint8_t *)pdb->data + page * PDB_PAGE_SIZE;
        void *dst = (uint8_t *)buffer + i * PDB_PAGE_SIZE;
        pdb_memcpy(dst, src, PDB_PAGE_SIZE);
    }
    return buffer;
}

static inline void *pdb_read_stream(pdb_t *pdb, pdb_stream_t stream) {
    return pdb_read_pages(pdb, stream.cp_size, stream.pages);
}

static pdb_hash_table_t pdb_read_hash_table(pdb_t *pdb, void *start) {
    uint32_t *offset = start;
    pdb_hash_table_t result;
    // Read the string buffer
    result.string_buf_size = *offset++;
    result.string_buf = (char *)offset;
    offset = (uint32_t *)((char *)offset + result.string_buf_size);
    // Read the rest of hash table
    result.size = *offset++;
    result.cap = *offset++;
    result.cw_bits_present = *offset++;
    result.bits_present = offset;
    offset += result.cw_bits_present;
    result.cw_bits_deleted = *offset++;
    result.bits_deleted = offset;
    offset += result.cw_bits_deleted;
    result.entries = (pdb_hash_table_entry_t *)offset;
    return result;
}

static int pdb_tpi_header_check(pdb_tpi_stream_header_t *header) {
    if(header->version != 20040203) {
        return PDB_UNSUPPORTED;
    }
    if(header->size != sizeof(pdb_tpi_stream_header_t)) {
        return PDB_BAD_FORMAT;
    }
    if(header->hash_stream_index == (uint16_t)-1) {
        return PDB_BAD_FORMAT;
    }
    if(header->hash_key_size != 4) {
        return PDB_UNSUPPORTED;
    }
    if(header->ti_begin != 0x1000) {
        return PDB_UNSUPPORTED;
    }
    return PDB_OK;
}

static uint32_t pdb_hash_string(char const *str) {
    uint32_t result = 0;
    uint32_t str_len = 0;
    for(char const *p = str; *p; ++p) {
        str_len += 1;
    }
    uint32_t nlongs = str_len/4;
    uint32_t *longs = (void *)str;
    for(uint32_t i = 0; i != nlongs; ++i) {
        result ^= longs[i];
    }
    uint32_t nremainder = str_len % 4;
    uint8_t *remainder = (void *)(longs + nlongs);
    // Maximum 3 bytes left. Hash 2 bytes if possible, then hash remaining
    // byte
    if(nremainder >= 2) {
        uint16_t value = *(uint16_t *)remainder;
        result ^= (uint32_t)value;
        remainder += 2;
        nremainder -= 2;
    }
    if(nremainder == 1) {
        result ^= *remainder;
    }
    const uint32_t to_lower_mask = 0x20202020;
    result |= to_lower_mask;
    result ^= (result >> 11);
    return result ^ (result >> 16);
}

static uint32_t pdb_hash_table_get_value(pdb_hash_table_t *tab, char const *name) {
    const uint32_t entry_size = sizeof(pdb_hash_table_entry_t);
    pdb_hash_table_entry_t *entries = tab->entries;
    uint32_t H = pdb_hash_string(name) % tab->cap;
    uint32_t I = H;
    do {
        pdb_hash_table_entry_t *entry = entries + I;
        if(entry->k == H) {
            return entry->v;
        }
        I = (I + 1) % tab->cap;
    } while(I != H);
    return 0;
}

static void pdb_type_array_init(pdb_type_array_t *array) {
    array->len = 0;
    array->cap = 0;
    array->types = NULL;
}

static uint32_t pdb_type_add(pdb_type_array_t *array, void *type) {
    if(array->len + 1 > array->cap) {
        uint32_t new_cap = 1 + 3 * array->cap / 2;
        array->types = pdb_realloc(array->types, new_cap*sizeof(void *));
        array->cap = new_cap;
    }
    uint32_t type_id = array->len;
    array->types[type_id] = type;
    array->len += 1;
    return type_id;
}

static void *pdb_type_get(pdb_type_array_t *array, uint32_t type_index) {
    pdb_assert(type_index >= 0x1000);
    type_index -= 0x1000;
    pdb_assert(type_index < array->len);
    return array->types[type_index];
}

static void pdb_load_types(pdb_type_array_t *array, void *start, void *end) {
    struct cv_type_header_t typedef cv_type_header_t;
    struct cv_type_header_t {
        uint16_t len;
        uint16_t kind;
    };
    uint8_t *types_stream = start;
    uint8_t *types_end = end;
    while(types_stream < types_end) {
        cv_type_header_t *record = (cv_type_header_t *)types_stream;
        if(record->kind == LF_PAD0) {
            goto next;
        }
        else {
            pdb_type_add(array, record);
        }
next:
        // Records must be on a 4-byte boundary
        record->len += sizeof(uint16_t);
        types_stream += (record->len + 3) & ~3;
    }
}

pdb_func char const *pdb_filename_for_module(size_t pe_size, void const *pe_data) {
    if(pe_size == 0) {
        // if pe_size is 0, we ignore module size by setting it to the max
        // value
        pe_size = (size_t)(-1);
    }
    char const *base = pe_data;
    // Check DOS header and PE headers for magic numbers and sizes
    pdb_dos_header_t const *dos_header = pe_data;
    if(pe_size < sizeof(pdb_dos_header_t)) {
        return NULL;
    }
    if(dos_header->magic != PDB_DOS_MAGIC) {
        return NULL;
    }
    if(dos_header->fa_new + sizeof(pdb_pe_header_t) >= pe_size) {
        return NULL;
    }
    pdb_pe_header_t const *pe_header = (void *)(base + dos_header->fa_new);
    if(pe_header->sig != PDB_PE_MAGIC) {
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

pdb_func int pdb_read(pdb_t *pdb, size_t buf_size, void *buf) {
    // Copy data
    pdb->data = buf;
    pdb->size = buf_size;
    // Verify the header
    typedef struct msf_header_t msf_header_t;
    struct msf_header_t {
        char magic[32];
        uint32_t cb_page;
        uint32_t fp_free_map;
        uint32_t cp_file;
        uint32_t cb_dir;
        uint32_t reserved;
        uint32_t fp_page_map;
    };
    msf_header_t *header = buf;
    if(pdb_strcmp(header->magic, pdb_msf_magic) != 0) {
        return PDB_BAD_FORMAT;
    }
    if(header->cb_page != PDB_PAGE_SIZE) {
        return PDB_UNSUPPORTED;
    }
    if(header->cp_file * PDB_PAGE_SIZE != buf_size) {
        return PDB_BAD_FORMAT;
    }
    pdb->cp_file = header->cp_file;
    // Read the stream directory
    uint32_t stream_dir_npages = pdb_ceildiv(header->cb_dir, PDB_PAGE_SIZE);
    uint32_t *stream_dir_pages = (uint32_t*)((uint8_t*)pdb->data + header->fp_page_map * PDB_PAGE_SIZE);
    if(header->fp_page_map + stream_dir_npages > header->cp_file + 1) {
        return PDB_BAD_FORMAT;
    }
    uint32_t *stream_dir = pdb_read_pages(pdb, stream_dir_npages, stream_dir_pages);
    if(stream_dir == NULL) {
        return PDB_BAD_FORMAT;
    }
    // Read the other stream data
    pdb->nstreams = stream_dir[0];
    pdb->streams = pdb_malloc(pdb->nstreams * sizeof(pdb_stream_t));
    for(uint32_t i = 0, op_stream = 1+pdb->nstreams; i != pdb->nstreams; ++i) {
        uint32_t cb_stream = stream_dir[1 + i];
        uint32_t cp_stream = pdb_ceildiv(cb_stream, PDB_PAGE_SIZE);
        pdb->streams[i].cb_size = cb_stream;
        pdb->streams[i].cp_size = cp_stream;
        pdb->streams[i].pages = stream_dir + op_stream;
        op_stream += cp_stream;
    }
    if(pdb->nstreams < 5) {
        return PDB_BAD_FORMAT;
    }
    // Read the PDB Info stream
    typedef struct pdb_info_stream_header_t pdb_info_stream_header_t;
    struct pdb_info_stream_header_t {
        uint32_t version;
        uint32_t signature;
        uint32_t age;
        uint8_t guid[16];
    };
    void *info_stream = pdb_read_stream(pdb, pdb->streams[1]);
    pdb_info_stream_header_t *info_stream_header = info_stream;
    if(info_stream_header->version != 20000404) {
        return PDB_BAD_FORMAT;
    }
    void *named_stream_map = info_stream_header + 1;
    pdb->named_stream_map = pdb_read_hash_table(pdb, named_stream_map);
    {
        uint32_t *feature_sigs;
        pdb_hash_table_entry_t *entries = pdb->named_stream_map.entries;
        feature_sigs = (uint32_t *)(entries + pdb->named_stream_map.size);
        uint32_t offset = (uint32_t)((uint8_t *)feature_sigs - info_stream);
        uint32_t remaining_bytes = pdb->streams[1].cb_size - offset;
        uint32_t nfeature_sigs = remaining_bytes / sizeof(uint32_t);
        for(int i = 0; i != nfeature_sigs; ++i) {
            if(feature_sigs[i] == 0x494E494D) {
                pdb->is_fastlink = true;
                break;
            }
        }
    }
    // Read the /names stream
    uint32_t names_idx;
    bool names_found = false;
    for(uint32_t i = 0; i != pdb->named_stream_map.size; ++i) {
        pdb_hash_table_entry_t *entry = &pdb->named_stream_map.entries[i];
        char *stream_name = &pdb->named_stream_map.string_buf[entry->stream_name];
        if(strcmp(stream_name, "/names") == 0) {
            names_found = true;
            names_idx = entry->stream_index;
        }
    }
    if(!names_found) {
        return PDB_BAD_FORMAT;
    }
    pdb->names_stream = pdb->streams[names_idx];
    // ...
    // Read the TPI and IPI streams, build the index->Type hashtable
    int code;
    pdb_type_array_init(&pdb->tpi_types);
    pdb_type_array_init(&pdb->ipi_types);
    void *tpi_stream = pdb_read_stream(pdb, pdb->streams[2]);
    if(tpi_stream == NULL) {
        return PDB_BAD_FORMAT;
    }
    pdb_tpi_stream_header_t *tpi_header = tpi_stream;
    if((code = pdb_tpi_header_check(tpi_header)) != PDB_OK) {
        return code;
    }
    void *tpi_types_start = tpi_header + 1;
    void *tpi_types_end = (uint8_t *)tpi_types_start + tpi_header->tr_bytes;
    pdb_load_types(&pdb->tpi_types, tpi_types_start, tpi_types_end);
    void *ipi_stream = pdb_read_stream(pdb, pdb->streams[4]);
    if(ipi_stream == NULL) {
        return PDB_BAD_FORMAT;
    }
    pdb_tpi_stream_header_t *ipi_header = ipi_stream;
    if((code = pdb_tpi_header_check(ipi_header)) != PDB_OK) {
        return code;
    }
    void *ipi_types_start = ipi_header + 1;
    void *ipi_types_end = (uint8_t *)ipi_types_start + ipi_header->tr_bytes;
    pdb_load_types(&pdb->ipi_types, ipi_types_start, ipi_types_end);
    // Read the DBI stream
    struct dbi_flags_t typedef dbi_flags_t;
    struct dbi_flags_t {
        uint16_t is_incremental : 1;
        uint16_t has_private_symbols : 1;
        uint16_t has_conflicting_types : 1;
        uint16_t reserved : 13;
    };
    pdb_assert((sizeof(uint16_t) == sizeof(dbi_flags_t)));
    struct dbi_stream_header_t typedef dbi_stream_header_t;
    struct dbi_stream_header_t {
        int32_t version_sig;
        uint32_t version_hdr;
        uint32_t age;
        uint16_t global_stream_idx;
        uint16_t build_number;
        uint16_t public_stream_idx;
        uint16_t pdb_dll_ver;
        uint16_t sym_record_stream;
        uint16_t pdb_dll_rebuild;
        int32_t cb_mod_info;
        int32_t cb_sec_contrib;
        int32_t cb_sec_map;
        int32_t cb_src_info;
        int32_t cb_type_srv_map;
        uint32_t mfc_type_srv_idx;
        int32_t cb_opt_dbg_hdr;
        int32_t cb_ec_substream;
        dbi_flags_t flags;
        uint16_t machine;
        uint32_t pad;
    };
    void *dbi_stream = pdb_read_stream(pdb, pdb->streams[3]);
    dbi_stream_header_t *dbi_header = dbi_stream;
    if(dbi_header->version_hdr != 19990903) {
        return PDB_UNSUPPORTED;
    }
    pdb->is_incremental = dbi_header->flags.is_incremental;
    pdb->has_private_symbols = dbi_header->flags.has_private_symbols;
    pdb->has_conflicting_types = dbi_header->flags.has_conflicting_types;
    if(dbi_header->machine != 0x8664 && dbi_header->machine != 0x14C) {
        return PDB_UNSUPPORTED;
    }
    uint32_t offset = 0;
    offset += sizeof(dbi_stream_header_t);
    uint32_t offs_mod_info = offset;
    uint32_t offs_sec_contrib = (offset += dbi_header->cb_mod_info);
    uint32_t offs_sec_map = (offset += dbi_header->cb_sec_contrib);
    uint32_t offs_src_info = (offset += dbi_header->cb_sec_map);
    uint32_t offs_type_srv_map = (offset += dbi_header->cb_src_info);
    uint32_t offs_opt_dbg_hdr = (offset += dbi_header->cb_type_srv_map);
    uint32_t offs_ec_substream = (offset += dbi_header->cb_opt_dbg_hdr);
    offset += dbi_header->cb_ec_substream;
    if(offset != pdb->streams[3].cb_size) {
        return PDB_BAD_FORMAT;
    }
    // Read ModInfo substream
    struct dbi_mod_info_t typedef dbi_mod_info_t;
    struct dbi_mod_info_t {
        uint32_t unused1;
        struct sec_contrib_entry {
            uint16_t section;
            char pad1[2];
            int32_t offset;
            int32_t size;
            uint32_t characteristics;
            uint16_t mod_index;
            char pad2[2];
            uint32_t data_crc;
            uint32_t reloc_crc;
        } sec_contrib;
        uint16_t flags;
        uint16_t mod_sym_stream;
        uint32_t sym_byte_size;
        uint32_t c11_byte_size;
        uint32_t c13_byte_size;
        uint16_t src_file_count;
        char pad[2];
        uint32_t unused2;
        uint32_t src_fn_index;
        uint32_t pdb_file_path_index;
        char mod_name[];
        // char obj_file_name[];
    };
    void *mod_info_stream = (void *)((uint8_t *)dbi_stream + offs_mod_info);
    dbi_mod_info_t *mod_info = mod_info_stream;
    printf("%s\n", mod_info->mod_name);
    return PDB_OK;
}

#endif // pdb_implementation
