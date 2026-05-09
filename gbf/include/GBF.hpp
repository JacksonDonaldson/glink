#ifndef GBF_HPP
#define GBF_HPP

#include "LocalBufferFile.hpp"

class GBF {
private:
    LocalBufferFile lbf_;
    uint master_table_offset_ = 0;
public:
    ErrorCode open(const char* gbf_file_path);
    uint getMasterTableOffset() const { return master_table_offset_; }
    LocalBufferFile& getLBF() { return lbf_; }
};

#endif