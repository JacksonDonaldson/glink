#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "localbufferfile.h"
#include "gbf.h"
#include "common.h"



uint get_gbf_file(const char *ghidra_repo_path, char *program_name, char* gbf_file_path_out, uint gbf_file_path_size) {
    char internal_ghidra_path[MAX_PATH];
    strncpy(internal_ghidra_path, ghidra_repo_path, sizeof(internal_ghidra_path) - 1);
    internal_ghidra_path[sizeof(internal_ghidra_path) - 1] = '\0';

    if(strncmp(internal_ghidra_path + strlen(internal_ghidra_path) - 4, ".gbf", 4) == 0){
        //Transform gbf to gbf? sure
        strncpy(gbf_file_path_out, internal_ghidra_path, gbf_file_path_size - 1);
        gbf_file_path_out[gbf_file_path_size - 1] = '\0';
        return E_OK;
    }    

    if (strncmp(internal_ghidra_path + strlen(internal_ghidra_path) - 4, ".gpr", 4) == 0) {
        //.gpr is just the pointer to the directory. Assume they want the repo w/ the same name.
        internal_ghidra_path[strlen(internal_ghidra_path) - 4] = '\0';
        strcat(internal_ghidra_path, ".rep");
    }

    if(strncmp(internal_ghidra_path + strlen(internal_ghidra_path) - 4, ".rep", 4)){
        return E_NOT_GHIDRA_REPO;
    }


    char index_dat_path[MAX_PATH];
    snprintf(index_dat_path, sizeof(index_dat_path), "%s/idata/~index.dat", internal_ghidra_path);

    FILE *index_dat_file = fopen(index_dat_path, "r");
    if (!index_dat_file) {
        return E_NO_INDEX;
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
        return E_NO_GBF_FILE;
    }

    char folder_0 = *(match - 5);
    char folder_1 = *(match - 4);

    *(match-1) = '\0';

    char gbf_folder_path[MAX_PATH];
    snprintf(gbf_folder_path, sizeof(gbf_folder_path), "%s/idata/%c%c/~%s.db/", internal_ghidra_path, folder_0, folder_1, match - 9);

    DIR *dir = opendir(gbf_folder_path);
    if (!dir) {
        return E_NO_GBF_FILE;
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
                strncpy(gbf_file_path_out, candidate_path, gbf_file_path_size - 1);
                gbf_file_path_out[gbf_file_path_size - 1] = '\0';
                newest_mtime = st.st_mtime;
                found = 1;
            }
        }
    }

    closedir(dir);

    if (!found) {
        return E_NO_GBF_FILE;
    }

    return E_OK;
}

uint open_gbf(const char* gbf_file_path, gbf * gbuf) {

    int res = create_localbufferfile(gbf_file_path, &gbuf->lbf);
    if (res != 0) {
        return res;
    }

    byte * master_buf = get_buffer(&gbuf->lbf, 1);

    if (master_buf[0] != 0x09) {
        return E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION;
    }
    uint size = readint(master_buf, 1);
    if(size < 9){
        return E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION;
    }
    byte version = master_buf[5];
    if(version != 0x01){
        return E_INVALID_GBF_UNSUPPORTED_GHIDRA_VERSION;
    }

    uint master_table_offset = readint(master_buf, 6);

    free(master_buf);
    gbuf->master_table_offset = master_table_offset;

    return E_OK;
}

//if table_name is found, fills out gbftable
uint get_gbftable(gbf* gbuf, char* table_name, gbftable * data) {
    memset(data, 0, sizeof(gbftable));

    // Read the master table
    byte *master_table = get_buffer(&gbuf->lbf, gbuf->master_table_offset + 1);

    uint target_len = strlen(table_name);
    if (target_len >= 0x80){
        return E_NAME_TOO_LONG;
    }

    byte node_type = master_table[0];
    if (node_type != 0x01) {
        return E_INVALID_NODE_TYPE;
    }

    uint record_count = readint(master_table, 1);
    // printf("master table has %u records\n", record_count);
    uint record_base_offset = 13;
    for(int i = 0; i < record_count; i++){
        // long long key = readlong(master_table, record_base_offset + i * 13);
        uint rec_offset = readint(master_table, record_base_offset + i * 13 + 8);
        byte ind_flag = master_table[record_base_offset + i * 13 + 12];
        
        if(ind_flag == 0){
            //the record has been stored within a chained DBBuffer at rec_offset
            byte* record = master_table + rec_offset;
            uint table_name_len = readint(record, 0);
            // printf("processing table %.*s at %08x\n", table_name_len, record + 4, rec_offset);
            if(table_name_len != target_len){
                continue;
            }
            if(memcmp(record + 4, table_name, table_name_len) != 0){
                continue;
            }
            //we've found the table of interest. Let's actually fill out gbftable.
            data->lbf = &gbuf->lbf;

            memcpy(data->name, table_name, target_len);
            data->name[target_len] = '\0';
            

            record += table_name_len + 4;
            // printf("Found table: %s at %08x\n", table_name, rec_offset);
            data->schema_version = readint(record, 0);
            data->root_buffer_id = readint(record, 4);
            data->key_type = record[8];
            data->schema_field_types_len = readint(record, 9);
            uint original_field_types_len = data->schema_field_types_len ;
            if (data->schema_field_types_len > 0) {
                data->schema_field_types = malloc(data->schema_field_types_len);
                memcpy(data->schema_field_types, record + 13, data->schema_field_types_len);

                //check for extensions
                for(int j = 0; j < original_field_types_len; j++){
                    if(data->schema_field_types[j] == 0xff){
                        // found an extension

                        // only include non-extension bytes in schema_field_types
                        if(original_field_types_len == data->schema_field_types_len){
                            data->schema_field_types_len = j;
                        }

                        //see if this is a sparse index extension
                        if(j < original_field_types_len - 1 && data->schema_field_types[j+1] == 1){
                            //this is a sparse index extension
                            data->sparse_fields = data->schema_field_types + j + 2;
                            int sparse_count = 0;
                            while(j + 2 + sparse_count < original_field_types_len && data->schema_field_types[j + 2 + sparse_count] != 0xff){
                                sparse_count++;
                            }
                            data->sparse_fields_len = sparse_count;
                        }
                    }
                }
            }
            record = record + original_field_types_len + 13;
            data->schema_field_names_len = readint(record, 0);
            if (data->schema_field_names_len > 0) {
                data->schema_field_names = malloc(data->schema_field_names_len);
                memcpy(data->schema_field_names, record + 4, data->schema_field_names_len);
            }
            record = record + data->schema_field_names_len + 4;
            data->index_column = readint(record, 0);
            data->max_key = readlong(record, 4);
            data->record_count = readint(record, 12);
            free(master_table);
            return E_OK;
        }
    }

    free(master_table);
    return E_TABLE_NOT_FOUND;
}

uint open_first_record(gbftable *data, gbfrecord *record) {
    record->table_data = data;
    record->current_record = -1;
    record->buffer = get_buffer(record->table_data->lbf, record->table_data->root_buffer_id + 1);
    if(record->buffer[0] != 0x01){
        return E_INVALID_NODE_TYPE;
    }
    if(readint(record->buffer, 1) != record->table_data->record_count){
        return E_RECORD_COUNT_MISMATCH;
    }

    next_record(record);
    return E_OK;
}

uint close_record(gbfrecord *record) {
    free(record->buffer);
    return E_OK;
}

uint next_record(gbfrecord *record) {
    record->current_record++;
    if (record->current_record >= record->table_data->record_count) {
        return E_NO_MORE_RECORDS;
    }
    record->id = readlong(record->buffer, 13 + record->current_record * 13);
    return E_OK;
}

uint open_record_by_id(gbftable* data, gbfrecord *record, unsigned long long id) {
    record->table_data = data;
    record->buffer = get_buffer(record->table_data->lbf, record->table_data->root_buffer_id + 1);
    if(record->buffer[0] != 0x01){
        return E_INVALID_NODE_TYPE;
    }
    if(readint(record->buffer, 1) != record->table_data->record_count){
        return E_RECORD_COUNT_MISMATCH;
    }

    for(record->current_record = 0; record->current_record < record->table_data->record_count; record->current_record++){
        unsigned long long current_id = readlong(record->buffer, 13 + record->current_record * 13);
        if(current_id == id){
            record->id = current_id;
            return E_OK;
        }
    }
    return E_RECORD_NOT_FOUND;
}

byte * get_record_buffer(gbfrecord *record) {
    uint record_offset = readint(record->buffer, 21 + record->current_record * 13);
    return record->buffer + record_offset;
}

uint handle_field(byte field_type, byte ** record_buffer_ptr, void *out, uint out_len, uint want_output) {
    byte* record_buffer = *record_buffer_ptr;
    short tempshort;
    uint tempuint;
    long long templong;

    switch(field_type){
        case 0x00: // BYTE
            if(want_output){
                if(out_len < 1){
                    return E_INSUFFICIENT_SPACE;
                }
                memcpy(out, record_buffer, 1);
            }
            record_buffer += 1;
            break;
        case 0x01: // SHORT
            if(want_output){
                if(out_len < 2){
                    return E_INSUFFICIENT_SPACE;
                }
                tempshort = readshort(record_buffer, 0);
                memcpy(out, &tempshort, 2);
            }
            record_buffer += 2;
            break;
        case 0x02: // INT
            if(want_output){
                if(out_len < 4){
                    return E_INSUFFICIENT_SPACE;
                }
                tempuint = readint(record_buffer, 0);
                memcpy(out, &tempuint, 4);
            }
            record_buffer += 4;
            break;
        case 0x03: // LONG
            if(want_output){
                if(out_len < 8){
                    return E_INSUFFICIENT_SPACE;
                }
                templong = readlong(record_buffer, 0);
                memcpy(out, &templong, 8);
            }
            record_buffer += 8;
            break;
        case 0x04: // STRING
            int str_len = readint(record_buffer, 0);
            if(str_len < 0){
                str_len = 0;
            }
            if(want_output){
                if(out_len < str_len + 1){
                    return E_INSUFFICIENT_SPACE;
                }
                memcpy(out, record_buffer + 4, str_len);
                ((char*)out)[str_len] = '\0';
            }
            record_buffer += 4 + str_len;
            break;
        case 0x05: // BINARY
            uint bin_len = readint(record_buffer, 0);
            if(want_output){
                if(out_len < bin_len){
                    return E_INSUFFICIENT_SPACE;
                }
                memcpy(out, record_buffer + 4, bin_len);
            }
            record_buffer += 4 + bin_len;
            break;
        case 0x06: // BOOLEAN
            if(want_output){
                if(out_len < 1){
                    return E_INSUFFICIENT_SPACE;
                }
                memcpy(out, record_buffer, 1);
            }
            record_buffer += 1;
            break;
        case 0x07: // FIXED_10_TYPE
            if(want_output){
                if(out_len < 10){
                    return E_INSUFFICIENT_SPACE;
                }
                memcpy(out, record_buffer, 10);
            }
            record_buffer += 10;
            break;
        default:
            return E_UNSUPPORTED_FIELD_TYPE;
    }
    *record_buffer_ptr = record_buffer;
    return 0;
}

uint get_record_field(gbfrecord *record, char *target_name, void *out, uint out_len) {
    char* field_names_ptr = record->table_data->schema_field_names;
    uint target_name_len = strlen(target_name);

    byte* record_buffer = get_record_buffer(record);
    //skip the first field name (it's the primary key name)
    char* after_semicolon = strstr(field_names_ptr, ";");
    if(after_semicolon == NULL){
        return E_CORRUPT_FIELD_NAMES;
    }
    field_names_ptr = after_semicolon + 1;
    //then search for the target name
    uint target_field_index = -1;
    uint field_count = record->table_data->schema_field_types_len;
    for(int i = 0; i < field_count; i++){
        after_semicolon = strstr(field_names_ptr, ";");
        if(after_semicolon == NULL){
            return E_CORRUPT_FIELD_NAMES;
        }
        uint field_name_len = after_semicolon - field_names_ptr;
        if(field_name_len == target_name_len && memcmp(field_names_ptr, target_name, field_name_len) == 0){
            target_field_index = i;
            break;
        } else {
            field_names_ptr = after_semicolon + 1;
        }
    }
    if(target_field_index == -1){
        return E_FIELD_NOT_IN_SCHEMA;
    }

    //field_names_ptr += 4;
    int sparse_offset = record->table_data->schema_field_types_len - record->table_data->sparse_fields_len;
    uint record_count = record->table_data->schema_field_types_len; 
    for(int i = 0; i < record_count; i++){
        byte field_type = record->table_data->schema_field_types[i];
        byte field_index = i;
        // check sparsity
        if ( i == sparse_offset){
            byte sparse_data_count = record_buffer[0];
            record_count = i + sparse_data_count;
            record_buffer++;

        }
        if(i >= sparse_offset){
            field_index = record_buffer[0];
            field_type = record->table_data->schema_field_types[field_index];
            record_buffer++;
        }
        
        int want_output = field_index == target_field_index;
        uint result = handle_field(field_type, &record_buffer, out, out_len, want_output);
        
        if(result){
            return result;
        }
        if(want_output){
            return E_OK;
        }
    }
    return E_FIELD_NOT_FOUND;
}

void print_gbftable(gbftable * data) {
    printf("gbftable:\n");
    printf("  name: %s\n", data->name);
    printf("  schema version: %u\n", data->schema_version);
    printf("  root buffer id: %u\n", data->root_buffer_id);
    printf("  key type: %u\n", data->key_type);
    printf("  schema field types length: %u\n    ", data->schema_field_types_len);
    for(int i = 0; i < data->schema_field_types_len; i++){
        printf("%02x ", data->schema_field_types[i]);
    }
    printf("\n");
    printf("  schema sparse fields length: %u\n    ", data->sparse_fields_len);
    for(int i = 0; i < data->sparse_fields_len; i++){
        printf("%02x ", data->sparse_fields[i]);
    }
    printf("\n");
    printf("  schema field names length: %u\n    %s\n", data->schema_field_names_len, data->schema_field_names);
    printf("  index column: %u\n", data->index_column);
    printf("  max key: %lld\n", data->max_key);
    printf("  record count: %u\n", data->record_count);
}

void print_record(gbfrecord *record) {
    printf("gbfrecord:\n");
    char *field_names = record->table_data->schema_field_names;
    char *field_start = strstr(field_names, ";") + 1;
    if(field_start == NULL) {
        printf("  No field names found.\n");
        return;
    }
    char *field_end;
    int field_idx = 0;

    while ((field_end = strchr(field_start, ';')) != NULL) {
        int name_len = field_end - field_start;
        if (name_len > 0) {
            char field_name[256];
            if (name_len >= sizeof(field_name))
                name_len = sizeof(field_name) - 1;
            memcpy(field_name, field_start, name_len);
            field_name[name_len] = '\0';

            // Try to get the field value as bytes (max 64 bytes for printing)
            unsigned char buf[64];
            int result = get_record_field(record, field_name, buf, sizeof(buf));
            fflush(stdout);
            if (result == 0) {
                printf("  %s: ", field_name);
                byte type = record->table_data->schema_field_types[field_idx];
                if (type == 0x00 || type == 0x06) {
                    // BYTE or BOOLEAN
                    printf("%02x\n", *(byte*)buf);
                } else if (type == 0x01) {
                    // SHORT
                    printf("%04x\n", *(short*)buf);
                } else if (type == 0x02) {
                    // INT
                    printf("%08x\n", *(int*)buf);
                } else if (type == 0x03) {
                    // LONG
                    printf("%016llx\n", *(long long*)buf);
                } else if (type == 0x04) {
                    // STRING
                    printf("%s\n", buf);
                } else if (type == 0x05) {
                    // BINARY
                    printf("<binary data>\n");
                } else if (type == 0x07) {
                    // FIXED_10_TYPE
                    printf("<fixed 10-byte data>\n");
                } else {
                    printf("<unknown type>\n");
                }
            }
        }
        field_start = field_end + 1;
        field_idx++;
    }
}

void free_gbftable(gbftable * data) {
    if (data->schema_field_types_len > 0) {
        free(data->schema_field_types);
    }
    if (data->schema_field_names_len > 0) {
        free(data->schema_field_names);
    }

}