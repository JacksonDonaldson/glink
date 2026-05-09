#include "LocalBufferFile.hpp"
#include <cstring>

ErrorCode LocalBufferFile::create(const char* name) {
    file_ = std::fopen(name, "rb");
    if (!file_) return ErrorCode::E_FILE_NOT_FOUND;
    byte header[0x20];
    std::fread(header, sizeof(header), 1, file_);
    if (std::memcmp(header, local_buffer_magic_, 8) != 0) return ErrorCode::E_MAGIC_MISMATCH;
    if (header[0x13] != 0x01) return ErrorCode::E_UNSUPPORTED_VERSION;
    buf_len_ = (header[0x14] << 24) | (header[0x15] << 16) | (header[0x16] << 8) | header[0x17];
    buf_len_ -= BUFFER_PREFIX_SIZE;
    if (buf_len_ < 0x10 || buf_len_ > 0x100000) return ErrorCode::E_UNREASONABLE_BUFFER_LENGTH;
    return ErrorCode::E_OK;
}

std::unique_ptr<byte[]> LocalBufferFile::getBuffer(uint buf_num) {
    uint offset = buf_num * (buf_len_ + BUFFER_PREFIX_SIZE) + BUFFER_PREFIX_SIZE;
    std::fseek(file_, offset, SEEK_SET);
    auto buffer = std::make_unique<byte[]>(buf_len_);
    std::fread(buffer.get(), buf_len_, 1, file_);
    return buffer;
}