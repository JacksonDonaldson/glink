#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "localbufferfile.h"

byte local_buffer_magic[8] = { 0x2f, 0x30, 0x31, 0x2c, 0x34, 0x29, 0x2c, 0x2a };

void create_localbufferfile(char* name, localbufferfile * lbf) {
    FILE *gbf_file = fopen(name, "r");
    if (!gbf_file) {
        fprintf(stderr, "Error: Unable to open file %s\n", name);
        exit(1);
    }

    byte header[0x20];
    fread(&header, 0x20, 1, gbf_file);
    if (memcmp(header, local_buffer_magic, 8) != 0) {
        fprintf(stderr, "Error: Magic doesn't match localbufferfile\n");
        exit(1);
    }
    if(header[0x13] != 0x01) {
        fprintf(stderr, "Error: Only version 1 supported\n");
        exit(1);
    }

    lbf->file = gbf_file;
    lbf->buf_len = (header[0x14] << 24) | (header[0x15] << 16) | (header[0x16] << 8) | header[0x17];
    lbf->buf_len -= BUFFER_PREFIX_SIZE;
    if (lbf->buf_len < 0x10 || lbf->buf_len > 0x100000) {
        fprintf(stderr, "Error: Unreasonable buffer length\n");
        exit(1);
    }
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

void destroy_localbufferfile(localbufferfile * lbf) {
    fclose(lbf->file);
}