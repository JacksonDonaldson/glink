#include "FixedGBFRecord.hpp"
#include "GBFTable.hpp"
#include "common.hpp"
#include <iostream>
#include <cstring>
#include <string>

FixedGBFRecord::FixedGBFRecord(GBFTable* table, uint record_index) : table_data_(table), current_record_(record_index), valid_(true) {
    if (record_index >= table->getRecordCount()) {
        valid_ = false;
        return;
    }
    buffer_owner_ = table->getLBF()->getBuffer(table->getRootBufferId() + 1);
    buffer_ = buffer_owner_.get();
    // For fixed: header 13 bytes, then Key(8) + Rec(rec_size) per record
    uint rec_size = table->getRecordSize();
    id_ = readlong(buffer_, 13 + current_record_ * (8 + rec_size));
}

ErrorCode FixedGBFRecord::next() {
    if (!valid_) return ErrorCode::E_INVALID;
    ++current_record_;
    if (current_record_ >= table_data_->getRecordCount()) return ErrorCode::E_NO_MORE_RECORDS;
    uint rec_size = table_data_->getRecordSize();
    id_ = readlong(buffer_, 13 + current_record_ * (8 + rec_size));
    return ErrorCode::E_OK;
}

byte* FixedGBFRecord::getRecordBuffer() {
    if (!valid_) return nullptr;
    uint rec_size = table_data_->getRecordSize();
    uint offset = 13 + current_record_ * (8 + rec_size) + 8; // after Key
    return const_cast<byte*>(buffer_) + offset;
}

ErrorCode FixedGBFRecord::getField(const char* target_name, void* out, uint out_len) {
    if (!valid_) return ErrorCode::E_INVALID;
    std::string field_names = table_data_->getSchemaFieldNames();
    uint target_name_len = std::strlen(target_name);
    byte* record_buffer = getRecordBuffer();
    // skip first field name
    size_t semicolon_pos = field_names.find(';');
    if (semicolon_pos == std::string::npos) return ErrorCode::E_CORRUPT_FIELD_NAMES;
    std::string after_semicolon = field_names.substr(semicolon_pos + 1);
    // search for target
    uint target_field_index = static_cast<uint>(-1);
    uint field_count = table_data_->getSchemaFieldTypes().size();
    size_t start = 0;
    for (uint i = 0; i < field_count; ++i) {
        size_t end = after_semicolon.find(';', start);
        if (end == std::string::npos) return ErrorCode::E_CORRUPT_FIELD_NAMES;
        uint field_name_len = end - start;
        if (field_name_len == target_name_len && std::memcmp(after_semicolon.c_str() + start, target_name, field_name_len) == 0) {
            target_field_index = i;
            break;
        }
        start = end + 1;
    }
    if (target_field_index == static_cast<uint>(-1)) return ErrorCode::E_FIELD_NOT_IN_SCHEMA;
    // now parse the record
    const auto& field_types = table_data_->getSchemaFieldTypes();
    uint sparse_offset = field_types.size() - table_data_->getSparseFieldsLen();

    uint record_count = field_types.size();
    for (uint i = 0; i < record_count; ++i) {
        byte field_type = field_types[i];
        byte field_index = i;
        if (i == sparse_offset) {
            byte sparse_data_count = record_buffer[0];
            record_count = i + sparse_data_count;
            ++record_buffer;
        }
        if (i >= sparse_offset) {
            field_index = record_buffer[0];
            field_type = field_types[field_index];
            ++record_buffer;
        }
        bool want_output = field_index == target_field_index;
        ErrorCode result = handleField(field_type, &record_buffer, out, out_len, want_output);
        if (result != ErrorCode::E_OK) return result;
        if (want_output) return ErrorCode::E_OK;
    }
    return ErrorCode::E_FIELD_NOT_FOUND;
}

ErrorCode FixedGBFRecord::handleField(byte field_type, byte** record_buffer_ptr, void* out, uint out_len, bool want_output) {
    byte* record_buffer = *record_buffer_ptr;
    switch (field_type) {
        case 0x00: // BYTE
            if (want_output) {
                if (out_len < 1) return ErrorCode::E_INSUFFICIENT_SPACE;
                *(byte*)out = record_buffer[0];
            }
            record_buffer += 1;
            break;
        case 0x01: // SHORT
            if (want_output) {
                if (out_len < 2) return ErrorCode::E_INSUFFICIENT_SPACE;
                *(short*)out = readshort(record_buffer, 0);
            }
            record_buffer += 2;
            break;
        case 0x02: // INT
            if (want_output) {
                if (out_len < 4) return ErrorCode::E_INSUFFICIENT_SPACE;
                *(int*)out = readint(record_buffer, 0);
            }
            record_buffer += 4;
            break;
        case 0x03: // LONG
            if (want_output) {
                if (out_len < 8) return ErrorCode::E_INSUFFICIENT_SPACE;
                *(long long*)out = readlong(record_buffer, 0);
            }
            record_buffer += 8;
            break;
        case 0x04: // STRING
            {
                int str_len = readint(record_buffer, 0);
                if (str_len < 0) return ErrorCode::E_INVALID;
                if (want_output) {
                    if (out_len < (uint)str_len + 1) return ErrorCode::E_INSUFFICIENT_SPACE;
                    std::memcpy(out, record_buffer + 4, str_len);
                    ((char*)out)[str_len] = '\0';
                }
                record_buffer += 4 + str_len;
            }
            break;
        case 0x05: // BINARY
            {
                uint bin_len = readint(record_buffer, 0);
                if (want_output) {
                    if (out_len < bin_len) return ErrorCode::E_INSUFFICIENT_SPACE;
                    std::memcpy(out, record_buffer + 4, bin_len);
                }
                record_buffer += 4 + bin_len;
            }
            break;
        case 0x06: // BOOLEAN
            if (want_output) {
                if (out_len < 1) return ErrorCode::E_INSUFFICIENT_SPACE;
                *(byte*)out = record_buffer[0];
            }
            record_buffer += 1;
            break;
        case 0x07: // FIXED_10_TYPE
            if (want_output) {
                if (out_len < 10) return ErrorCode::E_INSUFFICIENT_SPACE;
                std::memcpy(out, record_buffer, 10);
            }
            record_buffer += 10;
            break;
        default:
            return ErrorCode::E_UNSUPPORTED_FIELD_TYPE;
    }
    *record_buffer_ptr = record_buffer;
    return ErrorCode::E_OK;
}

void FixedGBFRecord::print() {
    if (!valid_) {
        std::cout << "gbfrecord: invalid\n";
        return;
    }
    std::cout << "gbfrecord:\n";
    std::string field_names = table_data_->getSchemaFieldNames();
    size_t start = field_names.find(';');
    if (start == std::string::npos) {
        std::cout << "  No field names found.\n";
        return;
    }
    ++start;
    int field_idx = 0;
    while (true) {
        size_t end = field_names.find(';', start);
        if (end == std::string::npos) break;
        int name_len = end - start;
        if (name_len > 0) {
            std::string field_name = field_names.substr(start, name_len);
            std::cout << "  " << field_name << ": ";
            
            // Get the field type
            if (field_idx < (int)table_data_->getSchemaFieldTypes().size()) {
                byte field_type = table_data_->getSchemaFieldTypes()[field_idx];
                
                // Allocate a buffer and retrieve the field value
                byte buffer[1024];
                ErrorCode result = getField(field_name.c_str(), buffer, sizeof(buffer));
                
                if (result == ErrorCode::E_OK) {
                    // Print based on field type
                    switch (field_type) {
                        case 0x00: // BYTE
                            std::cout << (int)*(byte*)buffer;
                            break;
                        case 0x01: // SHORT
                            std::cout << *(short*)buffer;
                            break;
                        case 0x02: // INT
                            std::cout << *(int*)buffer;
                            break;
                        case 0x03: // LONG
                            std::cout << *(long long*)buffer;
                            break;
                        case 0x04: // STRING
                            std::cout << (char*)buffer;
                            break;
                        case 0x05: // BINARY
                            std::cout << "[binary data]";
                            break;
                        case 0x06: // BOOLEAN
                            std::cout << (*(byte*)buffer ? "true" : "false");
                            break;
                        case 0x07: // FIXED_10_TYPE
                            std::cout << "[fixed 10]";
                            break;
                        default:
                            std::cout << "[unknown]";
                    }
                } 
                // else {
                //     std::cout << "[error reading field]";
                // }
            }
            std::cout << "\n";
        }
        start = end + 1;
        ++field_idx;
    }
}