#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace des_sim {

// Cấu trúc đại diện cho một khối dữ liệu 64-bit (8 bytes) trong thuật toán DES
struct DESBlock {
    uint64_t value{0}; // Biến lưu trữ giá trị 64-bit của khối
    
    // Khởi tạo khối với giá trị mặc định là 0 nếu không truyền tham số
    explicit DESBlock(uint64_t v = 0) : value(v) {}

    // Các hàm chuyển đổi định dạng
    array<uint8_t, 8> to_bytes() const;                                         
    static DESBlock from_bytes(const vector<uint8_t>& data, size_t offset = 0); 
    string to_bin_str() const;                                                  
    string to_hex_str() const;                                                  
};

// Các hàm tiện ích xử lý mảng dữ liệu (chia khối, ghép khối và padding)
vector<DESBlock> split_into_blocks(const vector<uint8_t>& data);                  // Cắt dữ liệu thành các khối
vector<uint8_t> blocks_to_bytes(const vector<DESBlock>& blocks);                  
vector<uint8_t> pkcs7_pad(const vector<uint8_t>& data, uint8_t block_size = 8);   
vector<uint8_t> pkcs7_unpad(const vector<uint8_t>& data, uint8_t block_size = 8); 

}  // namespace des_sim