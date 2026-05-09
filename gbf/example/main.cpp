#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "GBF.hpp"
#include "GBFTable.hpp"
#include "GBFRecord.hpp"
#include "GBFUtils.hpp"

/*
1. Parse stdin, get path to ghidra repo, name of program
2. parse ~index.dat:
    - find the appropriate .gbf database file
3. parse .gbf file
    - find location of master table
    - find location of symbol table
    - find location of function data table
    - for each symbol in the symbol table, if it's a function match it w/ function data table and print appropriate data
*/
#define MAX_PATH 256

int main(int argc, char ** argv) {

    char* ghidra_path, *program_name;
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <ghidra_path>@<program_name>\n", argv[0]);
        std::exit(1);
    }

    char *at_sign = std::strchr(argv[1], '@');
    if (!at_sign) {
        std::fprintf(stderr, "Usage: %s <ghidra_path>@<program_name>\n", argv[0]);
        std::exit(1);
    }
    *at_sign = '\0';
    ghidra_path = argv[1];
    program_name = at_sign + 1;

    char gbf_file_path[MAX_PATH];

    // Parse ~index.dat to find the appropriate .gbf database file
    std::printf("Ghidra path: %s\n", ghidra_path);
    std::printf("Program name: %s\n", program_name);
    uint res = get_gbf_file(ghidra_path, program_name, gbf_file_path, sizeof(gbf_file_path));
    std::printf("GBF file path: %d %s\n", res, gbf_file_path);

    GBF gbuf;
    res = static_cast<uint>(gbuf.open(gbf_file_path));
    std::printf("open_gbf: %u\n", res);

    
    GBFTable function_data;
    GBFRecord function_entry;
    function_data.getTable(&gbuf, "Function Data");

    function_data.print();

    
    // get_iterator(&data, &entry);

    // do{
    //     entry.print();
    // } while(!entry.next());

    GBFTable data;
    GBFRecord entry;
    data.getTable(&gbuf, "Symbols");

    data.print();


    entry.openFirst(&data);

    do{
        byte sym_type;
        entry.getField("Symbol Type", &sym_type, sizeof(sym_type));
        if(sym_type == 5){
            entry.print();
            function_entry.openById(&function_data, entry.getId());
            function_entry.print();
            std::printf("\n\n\n");
        }
    }while (entry.next() == ErrorCode::E_OK);

    // close_gbf(&gbuf);
    
    return 0;

}