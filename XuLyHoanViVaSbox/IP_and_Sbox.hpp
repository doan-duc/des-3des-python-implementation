#pragma once
#include <cstdint>
#include <functional>
#include <utility>
#include <vector>
using namespace std;

namespace des_sim {
uint64_t permute_bits(uint64_t bits, const vector<int>& table, int input_size); // Dữ liệu đầu vào,Bảng hoán vị,Số bit đầu vào
uint64_t initial_permutation(uint64_t block_64); //  IP 
uint64_t final_permutation(uint64_t block_64);//  FP
pair<uint32_t, uint32_t> feistel_round( // 1 VÒNG FEISTEL
    uint32_t L, uint32_t R, uint64_t subkey, const function<uint32_t(uint32_t, uint64_t)>& f_fn, int round_num = 0, bool verbose = false
);
int sbox_lookup(int sbox_index, uint8_t six_bits);  // TRA S-BOX
uint32_t sbox_substitute(uint64_t bits_48);
uint32_t feistel_f(uint32_t R, uint64_t subkey);
}
