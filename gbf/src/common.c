#include "common.h"

short readshort(byte * buffer, int offset){
    return (buffer[offset] << 8) | buffer[offset+1];
}

int readint(byte * buffer, int offset){
    return (buffer[offset] << 24) | (buffer[offset+1] << 16) | (buffer[offset+2] << 8) | buffer[offset+3];
}
long long readlong(byte * buffer, int offset){
    return (long long)buffer[offset] << 56 | (long long)buffer[offset+1] << 48 | (long long)buffer[offset+2] << 40 | (long long)buffer[offset+3] << 32 |
           (long long)buffer[offset+4] << 24 | (long long)buffer[offset+5] << 16 | (long long)buffer[offset+6] << 8 | (long long)buffer[offset+7];
}