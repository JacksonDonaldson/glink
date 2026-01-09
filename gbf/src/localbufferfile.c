#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "localbufferfile.h"

#include "gbf.h"

byte local_buffer_magic[8] = { 0x2f, 0x30, 0x31, 0x2c, 0x34, 0x29, 0x2c, 0x2a };

uint create_localbufferfile(const char* name, localbufferfile * lbf) {
    FILE *gbf_file = fopen(name, "r");
    if (!gbf_file) {
        return E_FILE_NOT_FOUND;
    }

    byte header[0x20];
    fread(&header, 0x20, 1, gbf_file);
    if (memcmp(header, local_buffer_magic, 8) != 0) {
        return E_MAGIC_MISMATCH;
    }
    if(header[0x13] != 0x01) {
        return E_UNSUPPORTED_VERSION;
    }

    lbf->file = gbf_file;
    lbf->buf_len = (header[0x14] << 24) | (header[0x15] << 16) | (header[0x16] << 8) | header[0x17];
    lbf->buf_len -= BUFFER_PREFIX_SIZE;
    if (lbf->buf_len < 0x10 || lbf->buf_len > 0x100000) {
        return E_UNREASONABLE_BUFFER_LENGTH;
    }
    return E_OK;
}

uint get_buflen(localbufferfile * lbf){
    return lbf->buf_len;
}

byte* get_buffer(localbufferfile * lbf, uint buf_num){
    uint offset = buf_num * (lbf->buf_len + BUFFER_PREFIX_SIZE) + BUFFER_PREFIX_SIZE;
    
    fseek(lbf->file, offset, SEEK_SET);
    byte* buffer = malloc(lbf->buf_len);
    fread(buffer, lbf->buf_len, 1, lbf->file);
    return buffer;

}

uint destroy_localbufferfile(localbufferfile * lbf) {
    fclose(lbf->file);
    return E_OK;
}