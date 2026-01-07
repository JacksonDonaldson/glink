#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "gbf.h"

typedef unsigned int uint;
typedef unsigned char byte;
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
        fprintf(stderr, "Usage: %s <ghidra_path>@<program_name>\n", argv[0]);
        exit(1);
    }

    char *at_sign = strchr(argv[1], '@');
    if (!at_sign) {
        fprintf(stderr, "Usage: %s <ghidra_path>@<program_name>\n", argv[0]);
        exit(1);
    }
    *at_sign = '\0';
    ghidra_path = argv[1];
    program_name = at_sign + 1;

    char gbf_file_path[MAX_PATH];

    // Parse ~index.dat to find the appropriate .gbf database file
    uint res = get_gbf_file(ghidra_path, program_name, gbf_file_path, sizeof(gbf_file_path));
    printf("GBF file path: %d %s\n", res, gbf_file_path);

    gbf gbuf;
    res = open_gbf(gbf_file_path, &gbuf);
    printf("open_gbf: %u\n", res);

    
    gbftable function_data;
    gbfrecord function_entry;
    get_gbftable(&gbuf, "Function Data", &function_data);

    // print_gbftable(&function_data);

    
    // get_iterator(&data, &entry);

    // do{
    //     print_record(&entry);
    // } while(!next_record(&entry));

    gbftable data;
    gbfrecord entry;
    get_gbftable(&gbuf, "Symbols", &data);

    print_gbftable(&data);


    open_first_record(&data, &entry);

    do{
        byte sym_type;
        get_record_field(&entry, "Symbol Type", &sym_type, sizeof(sym_type));
        if(sym_type == 6){
            print_record(&entry);
            open_record_by_id(&function_data, &function_entry, entry.id);
            print_record(&function_entry);
            printf("\n\n\n");
        }
    }while (!next_record(&entry));

    // close_gbf(&gbuf);
    
    return 0;

}