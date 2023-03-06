
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define pdb_single_module
#define pdb_implementation
#include "pdb.h"

#include <Windows.h>
#include <assert.h>

char *read_entire_file(char const *fn, size_t *size) {
    FILE *f = fopen(fn, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
    *size = fsize;
    char *buffer = malloc(fsize);
    fread(buffer, fsize, 1, f);
    fclose(f);
    return buffer;
}

int main() {
    char const *mod_path = "test.exe";
    HMODULE image = LoadLibraryA(mod_path);
    char const *pdbfn = pdb_filename_for_module(0, (void *)image);
    if(pdbfn == NULL) {
        printf("Image is corrupted\n");
        return -1;
    }
    printf("PDB location: %s\n", pdbfn);
    pdb_t pdb;
    size_t file_size;
    char *file_data = read_entire_file(pdbfn, &file_size);
    if(pdb_read(&pdb, file_size, file_data) != PDB_OK) {
        printf("Not a valid PDB file\n");
        exit(1);
    }
    printf("Number of pages: %#x\n", pdb.cp_file);
    printf("Found %u streams\n", pdb.nstreams);
    for(uint32_t i = 0; i != 5; ++i) {
        pdb_stream_t stream = pdb.streams[i];
        printf("\t[%u]: Size %#x, Blocks {", i, stream.cb_size);
        for(uint32_t p = 0; p != stream.cp_size; ++p) {
            printf("%#x,", stream.pages[p]);
        }
        printf("}\n");
    }
    return 0;
}
