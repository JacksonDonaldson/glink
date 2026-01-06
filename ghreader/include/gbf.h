#include "localbufferfile.h"

#define E_NOT_FOUND 1
#define E_INVALID 2
#define E_EOF 3

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
} tabledata;

typedef struct {
    tabledata * table_data;
    byte* buffer;
    uint current_record;
    unsigned long long id;
} tablerecord;

uint find_master_table(char* gbf_file_path, localbufferfile* lbf);

uint get_tabledata_from_master_table(localbufferfile* lbf, char* table, uint master_table_offset, tabledata* table_data);

uint get_iterator(tabledata* table_data, tablerecord *entry);

uint next_record(tablerecord *entry);

uint get_record_by_id(tabledata* data, tablerecord *record, unsigned long long id);

uint get_record_field(tablerecord *record, char *target_name, void *out, uint out_len);

void print_tabledata(tabledata* table_data);

void print_record(tablerecord *record);

void free_tabledata(tabledata* table_data);


