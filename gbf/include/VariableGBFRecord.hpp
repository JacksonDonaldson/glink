#ifndef VARIABLEGBFRECORD_HPP
#define VARIABLEGBFRECORD_HPP

#include "GBFRecord.hpp"
#include <memory>

class VariableGBFRecord : public GBFRecord {
private:
    GBFTable* table_data_ = nullptr;
    std::unique_ptr<byte[]> buffer_owner_;
    const byte* buffer_ = nullptr;
    uint current_record_ = 0;
    unsigned long long id_ = 0;
    bool valid_ = false;
public:
    VariableGBFRecord(GBFTable* table, uint record_index);
    VariableGBFRecord(const VariableGBFRecord&) = delete;
    VariableGBFRecord& operator=(const VariableGBFRecord&) = delete;
    VariableGBFRecord(VariableGBFRecord&&) = default;
    VariableGBFRecord& operator=(VariableGBFRecord&&) = default;
    ErrorCode next() override;
    byte* getRecordBuffer() override;
    ErrorCode getField(const char* target_name, void* out, uint out_len) override;
    unsigned long long getId() const override { return id_; }
    void print() override;
private:
    ErrorCode handleField(byte field_type, byte** record_buffer_ptr, void* out, uint out_len, bool want_output);
};

#endif