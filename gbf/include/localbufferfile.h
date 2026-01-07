#ifndef LOCALBUFFERFILE_H
#define LOCALBUFFERFILE_H
#include "gbf.h"


#define BUFFER_PREFIX_SIZE 5


void create_localbufferfile(char * filename, localbufferfile * file);

void destroy_localbufferfile(localbufferfile * file);

int get_buf_len(localbufferfile * file);

// mallocs and fills a pointer to the buffer; you're responsible for freeing it.
byte* get_buffer(localbufferfile * file, uint buf_num);

#endif // LOCALBUFFERFILE_H