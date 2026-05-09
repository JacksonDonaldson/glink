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
    - find the appropriate .gbf symbolsbase file
3. parse .gbf file
    - find location of master table
    - find location of symbol table
    - find location of function symbols table
    - for each symbol in the symbol table, if it's a function match it w/ function symbols table and print appropriate symbols
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

    // Parse ~index.dat to find the appropriate .gbf symbolsbase file
    std::printf("Ghidra path: %s\n", ghidra_path);
    std::printf("Program name: %s\n", program_name);
    uint res = get_gbf_file(ghidra_path, program_name, gbf_file_path, sizeof(gbf_file_path));
    std::printf("GBF file path: %d %s\n", res, gbf_file_path);

    GBF gbuf;
    res = static_cast<uint>(gbuf.open(gbf_file_path));
    std::printf("open_gbf: %u\n", res);

    
    GBFTable thunk_functions;
    ErrorCode err = thunk_functions.getTable(&gbuf, "Thunk Functions");
    std::printf("get_gbftable: %d\n", err);

    thunk_functions.print();

    GBFTable function_data;
    err = function_data.getTable(&gbuf, "Function Data");
    std::printf("get_gbftable: %d\n", err);
    

    GBFTable symbols;
    
    symbols.getTable(&gbuf, "Symbols");

    symbols.print();


    auto entry2 = symbols.getFirstRecord();
    if (!entry2) {
        std::printf("No records in Symbols\n");
        exit(1);
    }

    do{
        byte sym_type;
        entry2->getField("Symbol Type", &sym_type, sizeof(sym_type));
        if(sym_type == 5){
            
            auto function_entry = thunk_functions.getRecordById(entry2->getId());
            if(function_entry){
                entry2->print();
                function_entry->print();
                ulonglong func_id;
                function_entry->getField("Linked Function ID", &func_id, sizeof(func_id));

                auto other_symbol = symbols.getRecordById(func_id);
                if(other_symbol){
                    other_symbol->print();
                }
                // auto function_data_entry = function_data.getRecordById(func_id);
                // function_data_entry->print();

                

            }
            std::printf("\n\n\n");
        }
    }while (entry2->next() == ErrorCode::E_OK);

    // close_gbf(&gbuf);
    
    return 0;

}