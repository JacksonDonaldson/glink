#ifndef LOCALBUFFERFILE_HPP
#define LOCALBUFFERFILE_HPP

#include "common.hpp"
#include <memory>
#include <cstdio>

class LocalBufferFile {
private:
    FILE* file_ = nullptr;
    uint buf_len_ = 0;
    static constexpr byte local_buffer_magic_[8] = { 0x2f, 0x30, 0x31, 0x2c, 0x34, 0x29, 0x2c, 0x2a };
    static constexpr uint BUFFER_PREFIX_SIZE = 5;
public:
    LocalBufferFile() = default;
    ~LocalBufferFile() { if (file_) std::fclose(file_); }
    ErrorCode create(const char* filename);
    uint getBufLen() const { return buf_len_; }
    std::unique_ptr<byte[]> getBuffer(uint buf_num);
};

#endif