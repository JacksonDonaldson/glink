#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

#include "plugin-api.h"
#include "GBF.hpp"
#include "GBFTable.hpp"
#include "GBFRecord.hpp"
#include "GBFUtils.hpp"

using ErrorCode = ::ErrorCode;

static ld_plugin_register_claim_file tv_register_claim_file = nullptr;
static ld_plugin_add_symbols add_symbols = nullptr;
static ld_plugin_get_symbols get_symbols = nullptr;
static ld_plugin_register_all_symbols_read tv_register_all_symbols_read = nullptr;
static ld_plugin_add_input_file add_input_file = nullptr;
static ld_plugin_message log_message = nullptr;

static void* handle = nullptr;
static std::vector<ld_plugin_symbol> symbols;
static std::vector<ulonglong> sym_addrs;
static unsigned int sym_count = 0;
static char option[MAX_PATH];
static char saved_elf_file[0x80] = {0};

static const char* fname = "glink.ld";
static const char* empty_fname = "empty.o";

static int get_unthunked_function_name(GBFTable* symbol_table, GBFTable* thunk_function_table, GBFRecord* symbol_record, char* name, uint name_len){
    if (!symbol_record || !symbol_table || !thunk_function_table || !name || name_len == 0) {
        return 1;
    }

    std::unique_ptr<GBFRecord> current_symbol_record;
    GBFRecord* current = symbol_record;

    ErrorCode res = current->getField("Name", name, name_len);
    if (res != ErrorCode::E_OK) {
        return 2;
    }

    while (name[0] == '\0') {
        auto thunk_record = thunk_function_table->getRecordById(current->getId());
        if (!thunk_record) {
            return 0;
        }

        ulonglong linked_id = 0;
        res = thunk_record->getField("Linked Function ID", &linked_id, sizeof(linked_id));
        if (res != ErrorCode::E_OK) {
            return 4;
        }

        current_symbol_record = symbol_table->getRecordById(linked_id);
        if (!current_symbol_record) {
            fprintf(stderr, "4");
            return 5;
        }

        current = current_symbol_record.get();
        res = current->getField("Name", name, name_len);
        if (res != ErrorCode::E_OK) {
            return 6;
        }
    }

    return 0;
}


static int read_symbols_from_ghidra_db(const char* gbf_path) {
    GBF gbuf;
    ErrorCode res = gbuf.open(gbf_path);
    if (res != ErrorCode::E_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to open ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
        return -1;
    }

    GBFTable symtab;
    res = symtab.getTable(&gbuf, "Symbols");
    if (res != ErrorCode::E_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to get symbol table from ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
        return -1;
    }

    GBFTable thunk_functions;
    res = thunk_functions.getTable(&gbuf, "Thunk Functions");
    if (res != ErrorCode::E_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to get function table from ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
        return -1;
    }

    GBFTable function_data;
    res = function_data.getTable(&gbuf, "Function Data");
    if (res != ErrorCode::E_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to get function data table from ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
        return -1;
    }

    auto sym_record = symtab.getFirstRecord();
    if (!sym_record) {
        log_message(LDPL_FATAL, "Glink plugin: failed to open first record of symbol table from ghidra gbf database: %s\n", gbf_path);
        return -1;
    }

    symbols.clear();
    sym_addrs.clear();
    sym_count = 0;

    do {
        byte sym_type = 0;
        res = sym_record->getField("Symbol Type", &sym_type, sizeof(sym_type));
        if (res != ErrorCode::E_OK) {
            log_message(LDPL_FATAL, "Glink plugin: failed to get symbol type field of symbol record from ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
            return -1;
        }

        if (sym_type == 5) {
            char sym_name[256] = {0};


            uint err = get_unthunked_function_name(&symtab, &thunk_functions, sym_record.get(), sym_name, sizeof(sym_name));
            if (err != 0) {
                log_message(LDPL_FATAL, "Glink plugin: failed to get symbol name field of symbol record from ghidra gbf database: %s %d\n", gbf_path, err);
                return -1;
            }



            if (sym_name[0] == '\0' || std::strcmp(sym_name, "(null)") == 0) {
                continue;
            }

            ulonglong addr = 0;
            res = sym_record->getField("Address", &addr, sizeof(addr));
            if (res != ErrorCode::E_OK) {
                log_message(LDPL_FATAL, "Glink plugin: failed to get symbol address field of symbol record from ghidra gbf database: %s %d\n", gbf_path, static_cast<int>(res));
                return -1;
            }

            fprintf(stderr, "symbol: %s, addr: %08llx\n", sym_name, addr);
            ld_plugin_symbol sym = {};
            sym.name = strdup(sym_name);
            sym.version = nullptr;
            sym.def = LDPK_DEF;
            sym.symbol_type = LDST_FUNCTION;
            sym.visibility = LDPV_DEFAULT;
            sym.section_kind = LDSSK_DEFAULT;
            sym.size = 0;
            sym.comdat_key = nullptr;
            sym.resolution = LDPR_PREVAILING_DEF;

            symbols.push_back(sym);
            sym_addrs.push_back(addr);
            sym_count++;
        }
    } while (sym_record->next() == ErrorCode::E_OK);

    return 0;
}

static void generate_minimal_object_file() {
    unsigned char* buf = reinterpret_cast<unsigned char*>(saved_elf_file);
    if (!((unsigned char)buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')) {
        log_message(LDPL_FATAL, "Glink plugin: Couldn't generate a minimal object file. Did you pass in any real .o files?\n");
        return;
    }

    int ei_class = saved_elf_file[4];
    int ei_data = saved_elf_file[5];

#define WRITE16(p,v) do { \
    if (ei_data == 2) { (p)[0] = static_cast<unsigned char>(((v) >> 8) & 0xff); (p)[1] = static_cast<unsigned char>((v) & 0xff); } \
    else { (p)[0] = static_cast<unsigned char>((v) & 0xff); (p)[1] = static_cast<unsigned char>(((v) >> 8) & 0xff); } \
} while (0)

#define WRITE32(p,v) do { \
    if (ei_data == 2) { (p)[0] = static_cast<unsigned char>(((v) >> 24) & 0xff); (p)[1] = static_cast<unsigned char>(((v) >> 16) & 0xff); (p)[2] = static_cast<unsigned char>(((v) >> 8) & 0xff); (p)[3] = static_cast<unsigned char>((v) & 0xff); } \
    else { (p)[0] = static_cast<unsigned char>((v) & 0xff); (p)[1] = static_cast<unsigned char>(((v) >> 8) & 0xff); (p)[2] = static_cast<unsigned char>(((v) >> 16) & 0xff); (p)[3] = static_cast<unsigned char>(((v) >> 24) & 0xff); } \
} while (0)

#define WRITE64(p,v) do { \
    if (ei_data == 2) { \
        (p)[0] = static_cast<unsigned char>(((v) >> 56) & 0xff); (p)[1] = static_cast<unsigned char>(((v) >> 48) & 0xff); (p)[2] = static_cast<unsigned char>(((v) >> 40) & 0xff); (p)[3] = static_cast<unsigned char>(((v) >> 32) & 0xff); \
        (p)[4] = static_cast<unsigned char>(((v) >> 24) & 0xff); (p)[5] = static_cast<unsigned char>(((v) >> 16) & 0xff); (p)[6] = static_cast<unsigned char>(((v) >> 8) & 0xff); (p)[7] = static_cast<unsigned char>((v) & 0xff); \
    } else { \
        (p)[0] = static_cast<unsigned char>((v) & 0xff); (p)[1] = static_cast<unsigned char>(((v) >> 8) & 0xff); (p)[2] = static_cast<unsigned char>(((v) >> 16) & 0xff); (p)[3] = static_cast<unsigned char>(((v) >> 24) & 0xff); \
        (p)[4] = static_cast<unsigned char>(((v) >> 32) & 0xff); (p)[5] = static_cast<unsigned char>(((v) >> 40) & 0xff); (p)[6] = static_cast<unsigned char>(((v) >> 48) & 0xff); (p)[7] = static_cast<unsigned char>(((v) >> 56) & 0xff); \
    } \
} while (0)

    size_t e_shoff_off = (ei_class == 2) ? 40 : 32;
    size_t e_ehsize_off = (ei_class == 2) ? 52 : 40;
    size_t e_shentsize_off = (ei_class == 2) ? 58 : 46;
    size_t e_shnum_off = (ei_class == 2) ? 60 : 48;
    size_t e_shstrndx_off = (ei_class == 2) ? 62 : 50;

    uint16_t ehsize = (ei_class == 2) ? 64 : 52;
    uint16_t shentsize = (ei_class == 2) ? 64 : 40;

    WRITE16(&buf[16], 3);

    if (ei_class == 2) {
        WRITE64(&buf[e_shoff_off], static_cast<uint64_t>(ehsize));
    } else {
        WRITE32(&buf[e_shoff_off], static_cast<uint32_t>(ehsize));
    }

    WRITE16(&buf[e_ehsize_off], ehsize);
    WRITE16(&buf[e_shentsize_off], shentsize);
    WRITE16(&buf[e_shnum_off], 1);
    WRITE16(&buf[e_shstrndx_off], 0);

    unsigned char sh[96] = {0};
    WRITE32(&sh[4], 3);

    FILE* f = std::fopen(empty_fname, "wb");
    if (!f) {
        log_message(LDPL_INFO, "Glink plugin: failed to create %s\n", empty_fname);
        return;
    }
    if (std::fwrite(buf, 1, ehsize, f) != ehsize) {
        std::fclose(f);
        return;
    }
    if (std::fwrite(sh, 1, shentsize, f) != shentsize) {
        std::fclose(f);
        return;
    }
    std::fclose(f);

#undef WRITE16
#undef WRITE32
#undef WRITE64
}

extern "C" {

static enum ld_plugin_status onclaim_file(const struct ld_plugin_input_file* file,
                                         int* claimed) {
    size_t name_len = std::strlen(file->name);
    if (name_len > 2 && std::strcmp(file->name + name_len - 2, ".o") == 0) {
        bool already_copied = ((static_cast<unsigned char>(saved_elf_file[0]) == 0x7f) &&
                               saved_elf_file[1] == 'E' && saved_elf_file[2] == 'L' && saved_elf_file[3] == 'F');
        if (!already_copied) {
            FILE* f = std::fopen(file->name, "rb");
            if (f) {
                std::fread(saved_elf_file, 1, sizeof(saved_elf_file), f);
                std::fclose(f);
            } else {
                log_message(LDPL_INFO, "Glink plugin: failed to open %s to read ELF header\n", file->name);
            }
        }
    }

    char gbf_path[MAX_PATH];
    uint res = get_gbf_file(file->name, option, gbf_path, sizeof(gbf_path));
    if (res) {
        *claimed = 0;
        return LDPS_OK;
    }

    *claimed = 1;
    handle = file->handle;

    if (read_symbols_from_ghidra_db(gbf_path)) {
        return LDPS_ERR;
    }

    res = add_symbols(handle, sym_count, symbols.data());
    std::fprintf(stderr, "Glink plugin: add syms (count %u) result %u\n", sym_count, res);

    return LDPS_OK;
}

static enum ld_plugin_status onall_symbols_read() {
    if (!handle) {
        log_message(LDPL_FATAL, "Glink plugin: found no ghidra database to claim\n");
        return LDPS_ERR;
    }

    get_symbols(handle, sym_count, symbols.data());

    FILE* f = std::fopen(fname, "w");
    if (!f) {
        log_message(LDPL_FATAL, "Glink plugin: failed to write linker script %s\n", fname);
        return LDPS_ERR;
    }

    for (unsigned int i = 0; i < sym_count; i++) {
        std::fprintf(f, "%s = 0x%016llx;\n",
                     symbols[i].name,
                     sym_addrs[i]);
    }
    std::fclose(f);
    log_message(LDPL_INFO, "Glink plugin: wrote linker script %s with %u symbols\n", fname, sym_count);

    if (add_input_file(fname) != LDPS_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to add linker script %s\n", fname);
        return LDPS_ERR;
    }

    generate_minimal_object_file();
    if (add_input_file(empty_fname) != LDPS_OK) {
        log_message(LDPL_FATAL, "Glink plugin: failed to add empty shared library to workaround ld bug\n");
        return LDPS_ERR;
    }

    return LDPS_OK;
}

enum ld_plugin_status onload(struct ld_plugin_tv* tv) {
    std::fprintf(stderr, "Glink plugin loaded successfully.\n");
    option[sizeof(option) - 1] = '\xff';
    while (tv->tv_tag != LDPT_NULL) {
        switch (tv->tv_tag) {
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
                std::strncpy(option, tv->tv_u.tv_string, sizeof(option) - 1);
                option[sizeof(option) - 1] = '\0';
                break;
            case LDPT_MESSAGE:
                log_message = tv->tv_u.tv_message;
                break;
            default:
                break;
        }
        tv++;
    }

    if (!tv_register_claim_file || !add_symbols || !tv_register_all_symbols_read ||
        !get_symbols || !add_input_file || !log_message) {
        if (!log_message) {
            std::fprintf(stderr, "Glink failed to find all required functions\n");
        } else {
            log_message(LDPL_FATAL, "Glink failed to find all required functions\n");
        }
        return LDPS_ERR;
    }

    if (option[sizeof(option) - 1] == '\xff') {
        log_message(LDPL_FATAL, "Glink plugin requires --plugin-opt [target program] option\n");
        return LDPS_ERR;
    }

    tv_register_claim_file(onclaim_file);
    tv_register_all_symbols_read(onall_symbols_read);

    return LDPS_OK;
}

} // extern "C"
