#ifndef GBFRECORD_HPP
#define GBFRECORD_HPP

#include "GBFTable.hpp"
#include <memory>

class GBFRecord {
private:
    GBFTable* table_data_ = nullptr;
    std::unique_ptr<byte[]> buffer_;
    uint current_record_ = 0;
    unsigned long long id_ = 0;
public:
    ErrorCode openFirst(GBFTable* table);
    ErrorCode next();
    ErrorCode openById(GBFTable* table, unsigned long long id);
    byte* getRecordBuffer();
    ErrorCode getField(const char* target_name, void* out, uint out_len);
    unsigned long long getId() const { return id_; }
    void print();
private:
    ErrorCode handleField(byte field_type, byte** record_buffer_ptr, void* out, uint out_len, bool want_output);
};

#endif