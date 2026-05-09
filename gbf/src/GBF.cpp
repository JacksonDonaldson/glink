#include "GBF.hpp"
#include "common.hpp"

ErrorCode GBF::open(const char* gbf_file_path) {
    ErrorCode res = lbf_.create(gbf_file_path);
    if (res != ErrorCode::E_OK) return res;
    auto master_buf = lbf_.getBuffer(1);
    if (master_buf[0] != 0x09) return ErrorCode::E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION;
    uint size = readint(master_buf.get(), 1);
    if (size < 9) return ErrorCode::E_INVALID_GBF_MAYBE_UNSUPPORTED_GHIDRA_VERSION;
    byte version = master_buf[5];
    if (version != 0x01) return ErrorCode::E_INVALID_GBF_UNSUPPORTED_GHIDRA_VERSION;
    master_table_offset_ = readint(master_buf.get(), 6);
    return ErrorCode::E_OK;
}