#ifndef GBFTABLE_HPP
#define GBFTABLE_HPP

#include "LocalBufferFile.hpp"
#include <string>
#include <vector>

class GBFTable {
private:
    std::string name_;
    uint schema_version_ = 0;
    uint root_buffer_id_ = 0;
    byte key_type_ = 0;
    std::vector<byte> schema_field_types_;
    uint sparse_fields_len_ = 0;
    std::vector<byte> sparse_fields_;
    std::string schema_field_names_;
    uint index_column_ = 0;
    long long max_key_ = 0;
    uint record_count_ = 0;
    LocalBufferFile* lbf_ = nullptr;
public:
    GBFTable() = default;
    ErrorCode getTable(class GBF* gbuf, const char* table_name);
    const std::string& getName() const { return name_; }
    uint getRecordCount() const { return record_count_; }
    uint getRootBufferId() const { return root_buffer_id_; }
    LocalBufferFile* getLBF() const { return lbf_; }
    const std::vector<byte>& getSchemaFieldTypes() const { return schema_field_types_; }
    const std::string& getSchemaFieldNames() const { return schema_field_names_; }
    uint getSparseFieldsLen() const { return sparse_fields_len_; }
    void print() const;
};

#endif