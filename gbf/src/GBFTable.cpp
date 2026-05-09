#include "GBFTable.hpp"
#include "GBF.hpp"
#include "common.hpp"
#include <iostream>
#include <cstring>

ErrorCode GBFTable::getTable(GBF* gbuf, const char* table_name) {
    name_ = table_name;
    lbf_ = &gbuf->getLBF();
    auto master_table = lbf_->getBuffer(gbuf->getMasterTableOffset() + 1);
    uint target_len = std::strlen(table_name);
    if (target_len >= 0x80) return ErrorCode::E_NAME_TOO_LONG;
    byte node_type = master_table[0];
    if (node_type != 0x01) return ErrorCode::E_INVALID_NODE_TYPE;
    uint record_count = readint(master_table.get(), 1);
    uint record_base_offset = 13;
    for (uint i = 0; i < record_count; ++i) {
        uint rec_offset = readint(master_table.get(), record_base_offset + i * 13 + 8);
        byte ind_flag = master_table[record_base_offset + i * 13 + 12];
        if (ind_flag == 0) {
            byte* record = master_table.get() + rec_offset;
            uint table_name_len = readint(record, 0);
            if (table_name_len != target_len) continue;
            if (std::memcmp(record + 4, table_name, table_name_len) != 0) continue;
            // found
            record += 4 + table_name_len;
            schema_version_ = readint(record, 0);
            root_buffer_id_ = readint(record, 4);
            key_type_ = record[8];
            uint schema_field_types_len = readint(record, 9);
            schema_field_types_.resize(schema_field_types_len);
            std::memcpy(schema_field_types_.data(), record + 13, schema_field_types_len);

            // Check for extensions
            uint logical_len = schema_field_types_len;
            bool found_extension = false;
            for (uint j = 0; j < schema_field_types_len; ++j) {
                if (schema_field_types_[j] == 0xff) {
                    // Found an extension
                    found_extension = true;
                    logical_len = j;

                    // See if this is a sparse index extension
                    if (j < schema_field_types_len - 1 && schema_field_types_[j + 1] == 1) {
                        // This is a sparse index extension
                        uint sparse_start = j + 2;
                        uint sparse_count = 0;
                        while (j + 2 + sparse_count < schema_field_types_len && schema_field_types_[j + 2 + sparse_count] != 0xff) {
                            ++sparse_count;
                        }
                        sparse_fields_len_ = sparse_count;
                        sparse_fields_.resize(sparse_count);
                        std::memcpy(sparse_fields_.data(), schema_field_types_.data() + sparse_start, sparse_count);
                    }
                    break; // Assuming only one extension
                }
            }

            if (found_extension) {
                schema_field_types_.resize(logical_len);
            }

            record += 13 + schema_field_types_len;
            uint schema_field_names_len = readint(record, 0);
            schema_field_names_.assign((char*)record + 4, schema_field_names_len);
            record += 4 + schema_field_names_len;
            index_column_ = readint(record, 0);
            max_key_ = readlong(record, 4);
            record_count_ = readint(record, 12);
            return ErrorCode::E_OK;
        }
    }
    return ErrorCode::E_TABLE_NOT_FOUND;
}

void GBFTable::print() const {
    std::cout << "gbftable:\n";
    std::cout << "  name: " << name_ << "\n";
    std::cout << "  schema version: " << schema_version_ << "\n";
    std::cout << "  root buffer id: " << root_buffer_id_ << "\n";
    std::cout << "  key type: " << (int)key_type_ << "\n";
    std::cout << "  schema field types length: " << schema_field_types_.size() << "\n    ";
    for (auto b : schema_field_types_) {
        std::cout << std::hex << (int)b << " ";
    }
    std::cout << "\n";
    std::cout << "  schema sparse fields length: " << sparse_fields_len_ << "\n    ";
    for (auto b : sparse_fields_) {
        std::cout << std::hex << (int)b << " ";
    }
    std::cout << "\n";
    std::cout << "  schema field names length: " << schema_field_names_.size() << "\n    " << schema_field_names_ << "\n";
    std::cout << "  index column: " << index_column_ << "\n";
    std::cout << "  max key: " << max_key_ << "\n";
    std::cout << "  record count: " << record_count_ << "\n";
}