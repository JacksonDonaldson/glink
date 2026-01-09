#ifndef LOCALBUFFERFILE_H
#define LOCALBUFFERFILE_H
#include "gbf.h"


#define BUFFER_PREFIX_SIZE 5


uint create_localbufferfile(const char * filename, localbufferfile * file);

uint destroy_localbufferfile(localbufferfile * file);

int get_buf_len(localbufferfile * file);

// mallocs and fills a pointer to the buffer; you're responsible for freeing it.
byte* get_buffer(localbufferfile * file, uint buf_num);

#endif // LOCALBUFFERFILE_H