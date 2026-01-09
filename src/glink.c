#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "plugin-api.h"
#include "gbf.h"

typedef unsigned int uint;
typedef unsigned long long ulonglong;
typedef unsigned char byte;

static ld_plugin_register_claim_file tv_register_claim_file = 0;
static ld_plugin_add_symbols add_symbols = 0;
static ld_plugin_get_symbols get_symbols = 0;
static ld_plugin_register_all_symbols_read tv_register_all_symbols_read = 0;
static ld_plugin_add_input_file add_input_file = 0;
static ld_plugin_message log;


static void* handle = 0;
struct ld_plugin_symbol *symbols;
ulonglong * sym_addrs;
unsigned int sym_count = 0;
static char option[MAX_PATH];


static uint read_symbols_from_ghidra_db(const char* gbf_path) {
    gbf gbuf;
    uint res = open_gbf((char*)gbf_path, &gbuf);
    if(res){
        log(LDPL_FATAL, "Glink plugin: failed to open ghidra gbf database: %s %u\n", gbf_path, res);
        return -1;
    }

    gbftable symtab;
    res = get_gbftable(&gbuf, "Symbols", &symtab);
    if(res){
        log(LDPL_FATAL, "Glink plugin: failed to get symbol table from ghidra gbf database: %s %u\n", gbf_path, res);
        return -1;
    }

    gbfrecord sym_record;
    res = open_first_record(&symtab, &sym_record);
    if(res){
        log(LDPL_FATAL, "Glink plugin: failed to open first record of symbol table from ghidra gbf database: %s %u\n", gbf_path, res);
        return -1;
    }

    uint list_size = 32;
    symbols = malloc(sizeof(struct ld_plugin_symbol) * list_size);
    sym_addrs = malloc(sizeof(ulonglong) * list_size);

    sym_count = 0;
    do{
        byte sym_type;
        res = get_record_field(&sym_record, "Symbol Type", &sym_type, sizeof(sym_type));
        if(res){
            log(LDPL_FATAL, "Glink plugin: failed to get symbol type field of symbol record from ghidra gbf database: %s %u\n", gbf_path, res);
            return -1;
        }

        if(sym_type == 5){ //function symbol
            char sym_name[256] = {0};
            res = get_record_field(&sym_record, "Name", sym_name, sizeof(sym_name));
            if(res){
                log(LDPL_FATAL, "Glink plugin: failed to get symbol name field of symbol record from ghidra gbf database: %s %u\n", gbf_path, res);
                return -1;
            }
            
            if(sym_name[0] == '\0' || strcmp(sym_name, "(null)") == 0){
                continue;
            }
            fprintf(stderr, "Glink plugin: found function symbol: %s\n", sym_name);
            symbols[sym_count].name = strdup(sym_name);
            symbols[sym_count].version = NULL;
            symbols[sym_count].def = LDPK_DEF;
            symbols[sym_count].symbol_type = LDST_FUNCTION;
            symbols[sym_count].visibility = LDPV_DEFAULT;
            symbols[sym_count].section_kind = LDSSK_DEFAULT;
            symbols[sym_count].size = 0; //unknown
            symbols[sym_count].comdat_key = NULL;
            symbols[sym_count].resolution = LDPR_PREVAILING_DEF; //regular

            ulonglong addr = 0;
            res = get_record_field(&sym_record, "Address", &addr, sizeof(addr));
            if(res){
                log(LDPL_FATAL, "Glink plugin: failed to get symbol address field of symbol record from ghidra gbf database: %s %u\n", gbf_path, res);
                return -1;
            }
            sym_addrs[sym_count] = addr;

            sym_count++;
            if(sym_count >= list_size){
                list_size *= 2;
                symbols = realloc(symbols, sizeof(struct ld_plugin_symbol) * list_size);
                sym_addrs = realloc(sym_addrs, sizeof(ulonglong) * list_size);
            }
        }
    } while(!next_record(&sym_record));
    return 0;
}

static enum ld_plugin_status onclaim_file(const struct ld_plugin_input_file *file,
                                         int* claimed)
{
    //glink handles .gbf database files; it'll grab the most recent of those if given
    //[program]@[ghidra_repository].gpr files

    char gbf_path[MAX_PATH];
    uint res = get_gbf_file(file->name, option, gbf_path, sizeof(gbf_path));
    if(res){
        *claimed = 0;
        return LDPS_OK;
    }
    *claimed = 1;
    handle = file->handle;

    res = read_symbols_from_ghidra_db(gbf_path);
    if(res){
        return LDPS_ERR;
    }
    return LDPS_OK;
}


const char* fname = "glink.ld";
static enum ld_plugin_status onall_symbols_read() {
    if(!handle) {
        log(LDPL_FATAL, "Glink plugin: found no ghidra database to claim\n");
        return LDPS_ERR;
    }

    get_symbols(handle, sym_count, symbols);
    

    FILE* f = fopen(fname, "w");
    for(int i = 0; i < sym_count; i++) {
        fprintf(f, "%s = 0x%016llx;\n",
                symbols[i].name,
                sym_addrs[i]);
    }
    fclose(f);
    log(LDPL_INFO, "Glink plugin: wrote linker script %s with %u symbols\n", fname, sym_count);
    // int v= add_input_file("a");
    int v = add_input_file(fname);
    if(v != LDPS_OK){
        log(LDPL_FATAL, "Glink plugin: failed to add linker script %s\n", fname);
        return LDPS_ERR;
    }
    // this is a workaround for a bug in ld;
    // adding only a linker script causes a hang
    // see https://sourceware.org/bugzilla/show_bug.cgi?id=33764
    v = add_input_file("empty.so");
    if(v != LDPS_OK){
        log(LDPL_FATAL, "Glink plugin: failed to add empty shared library to workaround ld bug\n");
        return LDPS_ERR;
    }

    return LDPS_OK;
}


enum ld_plugin_status onload (struct ld_plugin_tv *tv){
    fprintf(stderr, "Glink plugin loaded successfully.\n");
    option[sizeof(option) - 1] = '\xff';
    do{
        switch(tv->tv_tag){
        case LDPT_REGISTER_CLAIM_FILE_HOOK:
            tv_register_claim_file = tv->tv_u.tv_register_claim_file;
            break;
        case LDPT_ADD_SYMBOLS:
            add_symbols = tv->tv_u.tv_add_symbols;
            break;
        case LDPT_GET_SYMBOLS:
            get_symbols = tv->tv_u.tv_get_symbols;
            break;
        case LDPT_REGISTER_ALL_SYMBOLS_READ_HOOK:
            tv_register_all_symbols_read = tv->tv_u.tv_register_all_symbols_read;
            break;
        case LDPT_ADD_INPUT_FILE:
            add_input_file = tv->tv_u.tv_add_input_file;
            break;
        case LDPT_OPTION:
            strncpy(option, tv->tv_u.tv_string, sizeof(option) - 1);
            option[sizeof(option) - 1] = '\0';
            break;
        case LDPT_MESSAGE:
            log = tv->tv_u.tv_message;
            break;
        default:
            //ignore other tags
            break;
        }
        tv++;
    } while (tv->tv_tag != LDPT_NULL);

    if(!tv_register_claim_file || !add_symbols || !tv_register_all_symbols_read || !get_symbols || !add_input_file || !log) {
        if(!log){
            fprintf(stderr, "Glink failed to find all required functions");
        }
        else{
            log(LDPL_FATAL, "Glink failed to find all required functions\n");
        }
        return LDPS_ERR;
    }
    if(option[sizeof(option) - 1] == '\xff') {
        log(LDPL_FATAL, "Glink plugin requires --plugin-opt [target program] option\n");
        return LDPS_ERR;
    }
    

    tv_register_claim_file(onclaim_file);
    tv_register_all_symbols_read(onall_symbols_read);

    return LDPS_OK;
}