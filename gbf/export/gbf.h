#ifndef GBF_H
#define GBF_H
typedef unsigned char byte;
typedef unsigned int uint;



#define E_OK 0
#define E_NO_MORE_RECORDS 11
#define E_TABLE_NOT_FOUND 12
#define E_RECORD_NOT_FOUND 13
#define E_FIELD_NOT_FOUND 18

#define E_NOT_FOUND 1
#define E_INVALID 2
#define E_EOF 3
#define E_NOT_GHIDRA_REPO 4
#define E_NO_GBF_FILE 5
#define E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION 6
#define E_INVALID_GBF_UNSUPPORTED_GHIDRA_VERSION 7
#define E_NAME_TOO_LONG 8
#define E_INVALID_NODE_TYPE 9
#define E_RECORD_COUNT_MISMATCH 10
#define E_UNSUPPORTED_FIELD_TYPE 14
#define E_CORRUPT_FIELD_NAMES 15
#define E_FIELD_NOT_IN_SCHEMA 16
#define E_INSUFFICIENT_SPACE 17
#define E_FILE_NOT_FOUND 19
#define E_MAGIC_MISMATCH 20
#define E_UNSUPPORTED_VERSION 21
#define E_UNREASONABLE_BUFFER_LENGTH 22
#define E_NO_INDEX 23

#define MAX_PATH 256

typedef struct {
    FILE * file;
    uint buf_len;
} localbufferfile;

typedef struct {
    localbufferfile lbf;
    uint master_table_offset;
} gbf;

typedef struct {
    char name[0x80];
    uint schema_version;
    uint root_buffer_id;
    byte key_type;

    uint schema_field_types_len;
    byte *schema_field_types;
    
    uint sparse_fields_len;
    byte * sparse_fields;

    uint schema_field_names_len;
    char *schema_field_names;

    uint index_column;
    long long max_key;
    uint record_count;
    localbufferfile* lbf;
} gbftable;

typedef struct {
    gbftable * table_data;
    byte* buffer;
    uint current_record;
    unsigned long long id;
} gbfrecord;

/*
ghidra_repo path: path to the .gpr file or the .rep directory
program_name: program in ghidra repo to target
gbf_file_path_out: will contain path of most recently edited ghidra backing file

returns: 0 on success
*/
uint get_gbf_file(const char *ghidra_repo_path, char *program_name, char* gbf_file_path_out, uint gbf_file_path_size);

uint open_gbf(const char* gbf_file_path, gbf* gbuf);

// uint close_gbf(gbf* gbuf);

uint get_gbftable(gbf * gbuf, char* table_name, gbftable* table_data);

uint open_record_by_id(gbftable* data, gbfrecord *record, unsigned long long id);

uint open_first_record(gbftable* table_data, gbfrecord *entry);

uint close_record(gbfrecord *record);

uint next_record(gbfrecord *entry);

uint get_record_field(gbfrecord *record, char *target_name, void *out, uint out_len);

void print_gbftable(gbftable* table_data);

void print_record(gbfrecord *record);

#endif // GBF_H