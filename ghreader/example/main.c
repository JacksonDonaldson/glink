#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "localbufferfile.h"
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

// Parse ~index.dat to find the appropriate .gbf database file
// Return the path to the .gbf file
void parse_index_dat(char *ghidra_path, char *program_name, char* gbf_file_path, uint gbf_file_path_size) {

    printf("ghidra_path: %s\n", ghidra_path);
    printf("program_name: %s\n", program_name);

    //.gpr is just the pointer to the directory. Assume they want the repo w/ the same name.
    if (strncmp(ghidra_path + strlen(ghidra_path) - 4, ".gpr", 4) == 0) {
        ghidra_path[strlen(ghidra_path) - 4] = '\0';
        strcat(ghidra_path, ".rep");
    }

    char index_dat_path[MAX_PATH];
    snprintf(index_dat_path, sizeof(index_dat_path), "%s/idata/~index.dat", ghidra_path);
    printf("index.dat path: %s\n", index_dat_path);

    FILE *index_dat_file = fopen(index_dat_path, "r");
    if (!index_dat_file) {
        fprintf(stderr, "Error: Unable to open ~index.dat file. Is %s a ghidra repo?\n", ghidra_path);
        exit(1);
    }

    char* match = NULL;
    char index_data[MAX_PATH];
    while (fgets(index_data, sizeof(index_data), index_dat_file)) {
        if ((match = strstr(index_data, program_name))) {
            break;
        }
    }
    fclose(index_dat_file);

    if(!match || match - index_data < 9){
        fprintf(stderr, "Error: Unable to find .gbf database file for program %s in %s\n", program_name, index_dat_path);
        exit(1);
    }

    char folder_0 = *(match - 5);
    char folder_1 = *(match - 4);

    *(match-1) = '\0';

    char gbf_folder_path[MAX_PATH];
    snprintf(gbf_folder_path, sizeof(gbf_folder_path), "%s/idata/%c%c/~%s.db/", ghidra_path, folder_0, folder_1, match - 9);
    printf("gbf folder path: %s\n", gbf_folder_path);

    DIR *dir = opendir(gbf_folder_path);
    if (!dir) {
        fprintf(stderr, "Error: Unable to open directory %s: %s\n", gbf_folder_path, strerror(errno));
        exit(1);
    }

    struct dirent *entry;
    struct stat st;
    char candidate_path[MAX_PATH * 2];
    time_t newest_mtime = 0;
    int found = 0;

    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len < 4 || strcmp(entry->d_name + len - 4, ".gbf") != 0)
            continue;
        snprintf(candidate_path, sizeof(candidate_path), "%s%s", gbf_folder_path, entry->d_name);
        if (stat(candidate_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!found || st.st_mtime > newest_mtime) {
                strncpy(gbf_file_path, candidate_path, gbf_file_path_size - 1);
                gbf_file_path[gbf_file_path_size - 1] = '\0';
                newest_mtime = st.st_mtime;
                found = 1;
            }
        }
    }

    closedir(dir);

    if (!found) {
        fprintf(stderr, "Error: No .gbf files found in %s\n", gbf_folder_path);
        exit(1);
    }

    printf("Most recent .gbf file: %s\n", gbf_file_path);
    
}


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
    parse_index_dat(ghidra_path, program_name, gbf_file_path, sizeof(gbf_file_path));

    localbufferfile lbf;
    uint master_table_offset = find_master_table(gbf_file_path, &lbf);
    printf("master table offset: %u\n", master_table_offset);

    
    tabledata function_data;
    tablerecord function_entry;
    get_tabledata_from_master_table(&lbf, "Function Data", master_table_offset, &function_data);

    // print_tabledata(&data);

    
    // get_iterator(&data, &entry);

    // do{
    //     print_record(&entry);
    // } while(!next_record(&entry));

    tabledata data;
    tablerecord entry;
    get_tabledata_from_master_table(&lbf, "Symbols", master_table_offset, &data);

    print_tabledata(&data);


    get_iterator(&data, &entry);

    do{
        byte sym_type;
        get_record_field(&entry, "Symbol Type", &sym_type, sizeof(sym_type));
        if(sym_type == 6){
            print_record(&entry);
            get_record_by_id(&function_data, &function_entry, entry.id);
            print_record(&function_entry);
            printf("\n\n\n");
        }
    }while (!next_record(&entry));

    //iterate through symbols table to find functions
    
    return 0;

}