
#include <stdio.h>
#include <stdint.h>

#define pdb_single_module
#define pdb_implementation
#include "pdb.h"

#include <Windows.h>
#include <assert.h>

int main() {
    char const *mod_path = "test.exe";
    HMODULE image = LoadLibraryA(mod_path);
    char const *pdbfn = pdb_filename_for(0, (void *)image);
    if(pdbfn == NULL) {
        printf("Image is corrupted\n");
        return -1;
    }
    pdb_t pdb;
    if(!pdb_fopen(&pdb, pdbfn)) {
        printf("Error opening pdb file\n");
        return -1;
    }
    pdb_fclose(&pdb);
    return 0;
}
