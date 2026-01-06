#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "plugin-api.h"

static ld_plugin_register_claim_file tv_register_claim_file = 0;
static ld_plugin_add_symbols add_symbols = 0;
static ld_plugin_get_symbols get_symbols = 0;
static ld_plugin_register_all_symbols_read tv_register_all_symbols_read = 0;
static ld_plugin_add_input_file add_input_file = 0;
static ld_plugin_message log;


static void* handle = 0;
struct ld_plugin_symbol symbols[1];

static enum ld_plugin_status onclaim_file(const struct ld_plugin_input_file *file,
                                         int* claimed)
{
    //glink handles .gbf database files; it'll grab the most recent of those if given
    //[program]@[ghidra_repository].gpr files

    if(strncmp(file->name, "example/ghidra_repo/target_project.gpr", strlen("example/ghidra_repo/target_project.gpr")) == 0){
        if(handle){
            log(LDPL_WARNING, "Glink plugin: already claimed a ghidra database; ignoring %s\n", file->name);
            *claimed = 0;
            return LDPS_OK;
        }

        fprintf(stderr, "Glink plugin claimed file: %s\n", file->name);
        *claimed = 1;
        
        symbols[0].name = "test_sym";
        symbols[0].version = NULL;
        symbols[0].def = LDPK_DEF;
        symbols[0].symbol_type = LDST_VARIABLE;
        symbols[0].visibility = LDPV_DEFAULT;
        symbols[0].section_kind = LDSSK_DEFAULT;
        symbols[0].size = 4; //4 bytes
        symbols[0].comdat_key = NULL;
        symbols[0].resolution = LDPR_PREVAILING_DEF; //regular

        
        add_symbols(file->handle, 1, symbols);
        handle = file->handle;
    } else {
        *claimed = 0;
    }
    return LDPS_OK;
}


const char* fname = "glink.ld";
static enum ld_plugin_status onall_symbols_read() {
    if(!handle) {
        log(LDPL_FATAL, "Glink plugin: found no ghidra database to claim\n");
        return LDPS_ERR;
    }

    get_symbols(handle, 1, symbols);

    
    unsigned int sym_count = 1;

    FILE* f = fopen(fname, "w");
    for(int i = 0; i < sym_count; i++) {
        fprintf(f, "%s = 0x%08x;\n",
                symbols[i].name,
                0x401000);
    }
    fclose(f);
    fprintf(stderr, "Wrote linker script: %s\n", fname);
    // int v= add_input_file("a");
    int v = add_input_file(fname);

    // this is a workaround for a bug in ld;
    // adding only a linker script causes a hang
    // see https://sourceware.org/bugzilla/show_bug.cgi?id=33764
    add_input_file("empty.so");

    fprintf(stderr, "Added input file: %s %d\n", fname, v);
    return LDPS_OK;
}

static const char* option = 0;

enum ld_plugin_status onload (struct ld_plugin_tv *tv){
    fprintf(stderr, "Glink plugin loaded successfully.\n");

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
            option = tv->tv_u.tv_string;
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
    if(!option) {
        log(LDPL_FATAL, "Glink plugin requires --plugin-opt [target program] option\n");
        return LDPS_ERR;
    }
    

    tv_register_claim_file(onclaim_file);
    tv_register_all_symbols_read(onall_symbols_read);

    return LDPS_OK;
}