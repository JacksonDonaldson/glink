#ifndef COMMON_H
#define COMMON_H

typedef unsigned char byte;
typedef unsigned int uint;

short readshort(byte * buffer, int offset);

int readint(byte * buffer, int offset);

long long readlong(byte * buffer, int offset);

#endif // COMMON_H