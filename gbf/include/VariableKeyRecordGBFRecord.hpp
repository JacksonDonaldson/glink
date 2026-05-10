#ifndef VARIABLEKEYRECORDGBFRECORD_HPP
#define VARIABLEKEYRECORDGBFRECORD_HPP

#include "GBFRecord.hpp"
#include <memory>

class VariableKeyRecordGBFRecord : public GBFRecord {
private:
    GBFTable* table_data_ = nullptr;
    std::unique_ptr<byte[]> buffer_owner_;
    const byte* buffer_ = nullptr;
    uint current_record_ = 0;
    unsigned long long id_ = 0;
    bool valid_ = false;
    byte key_type_ = 0;
    uint key_count_ = 0;
public:
    VariableKeyRecordGBFRecord(GBFTable* table, uint record_index);
    VariableKeyRecordGBFRecord(const VariableKeyRecordGBFRecord&) = delete;
    VariableKeyRecordGBFRecord& operator=(const VariableKeyRecordGBFRecord&) = delete;
    VariableKeyRecordGBFRecord(VariableKeyRecordGBFRecord&&) = default;
    VariableKeyRecordGBFRecord& operator=(VariableKeyRecordGBFRecord&&) = default;
    ErrorCode next() override;
    byte* getRecordBuffer() override;
    ErrorCode getField(const char* target_name, void* out, uint out_len) override;
    unsigned long long getId() const override { return id_; }
    void print() override;
private:
    uint getKeySize() const;
    ErrorCode handleField(byte field_type, byte** record_buffer_ptr, void* out, uint out_len, bool want_output);
};

#endif
