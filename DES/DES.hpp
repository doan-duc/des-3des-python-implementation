#pragma once

#include "../DataTypes/Block_types.hpp"
#include "../DataTypes/Key_types.hpp"

#include <cstdint>
#include <vector>

using namespace std;

namespace des_sim {
// Hàm để giải mã/ mã hóa một khối DES với một khóa nhất định
uint64_t des_16_rounds(uint64_t block_64, const vector<uint64_t>& subkeys, bool encrypt = true, bool verbose = false);
// Hàm để giải mã/ mã hóa một khối DES với một khóa nhất định, có thể in chi tiết quá trình nếu verbose = true
DESBlock des_cipher(const DESBlock& block, const DESKey& key, bool encrypt = true, bool verbose = false);
}
