#ifndef GBFRECORD_HPP
#define GBFRECORD_HPP

#include "common.hpp"

class GBFTable;

class GBFRecord {
public:
    virtual ~GBFRecord() = default;
    virtual ErrorCode next() = 0;
    virtual byte* getRecordBuffer() = 0;
    virtual ErrorCode getField(const char* target_name, void* out, uint out_len) = 0;
    virtual unsigned long long getId() const = 0;
    virtual void print() = 0;
};

#endif