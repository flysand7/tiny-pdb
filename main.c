
#include <stdio.h>
#include <stdint.h>

#define pdb_implementation
#include "pdb.h"

#include <Windows.h>
#include <assert.h>

int main() {
    PDB pdb = {0};
    HMODULE image = LoadLibraryA("test.exe");
    if(!pdb_module_load(&pdb, image)) {
        printf("Error loading pdb file\n");
        return -1;
    }
    return 0;
}
