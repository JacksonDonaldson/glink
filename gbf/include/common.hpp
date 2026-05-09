#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>

typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long long ulonglong;

#define MAX_PATH 256

enum class ErrorCode {
    E_OK = 0,
    E_NO_MORE_RECORDS = 11,
    E_TABLE_NOT_FOUND = 12,
    E_RECORD_NOT_FOUND = 13,
    E_FIELD_NOT_FOUND = 18,
    E_NOT_FOUND = 1,
    E_INVALID = 2,
    E_EOF = 3,
    E_NOT_GHIDRA_REPO = 4,
    E_NO_GBF_FILE = 5,
    E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION = 6,
    E_INVALID_GBF_UNSUPPORTED_GHIDRA_VERSION = 7,
    E_NAME_TOO_LONG = 8,
    E_INVALID_NODE_TYPE = 9,
    E_RECORD_COUNT_MISMATCH = 10,
    E_UNSUPPORTED_FIELD_TYPE = 14,
    E_CORRUPT_FIELD_NAMES = 15,
    E_FIELD_NOT_IN_SCHEMA = 16,
    E_INSUFFICIENT_SPACE = 17,
    E_FILE_NOT_FOUND = 19,
    E_MAGIC_MISMATCH = 20,
    E_UNSUPPORTED_VERSION = 21,
    E_UNREASONABLE_BUFFER_LENGTH = 22,
    E_NO_INDEX = 23,
    E_NO_RECORDS = 24
};

short readshort(const byte * buffer, int offset);
int readint(const byte * buffer, int offset);
long long readlong(const byte * buffer, int offset);

#endif // COMMON_HPP