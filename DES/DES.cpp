#include "DES.hpp"
#include "../Subkeys/DES_subkeys.hpp"
#include "../XuLyHoanViVaSbox/IP_and_Sbox.cpp"
#include "../XuLyHoanViVaSbox/IP_and_Sbox.hpp"

#include <algorithm>

using namespace std;

namespace des_sim {
// Hàm thực hiện 16 vòng Feistel, trả về khối đã được mã hóa/giải mã
uint64_t des_16_rounds(uint64_t block_64, const vector<uint64_t>& subkeys, bool encrypt, bool verbose) {
    uint64_t permuted = initial_permutation(block_64);
    uint32_t L = static_cast<uint32_t>((permuted >> 32) & 0xFFFFFFFFu);
    uint32_t R = static_cast<uint32_t>(permuted & 0xFFFFFFFFu);
    vector<uint64_t> active_subkeys = subkeys;
    if (!encrypt) reverse(active_subkeys.begin(), active_subkeys.end());

    auto f_with_sbox = [](uint32_t r_val, uint64_t subkey_val) -> uint32_t { return feistel_f(r_val, subkey_val); };
    for (int rnd = 0; rnd < 16; ++rnd) {
        pair<uint32_t, uint32_t> round_result = feistel_round(L, R, active_subkeys[rnd], f_with_sbox, rnd + 1, verbose);
        L = round_result.first;
        R = round_result.second;
    }
    uint64_t pre_fp = (static_cast<uint64_t>(R) << 32) | L;
    return final_permutation(pre_fp);
}

// Hàm giải mã/ mã hóa một khối DES với một khóa nhất định
DESBlock des_cipher(const DESBlock& block, const DESKey& key, bool encrypt, bool verbose) {
    auto subkeys = generate_subkeys(key.value, false);
    uint64_t out = des_16_rounds(block.value, subkeys, encrypt, verbose);
    return DESBlock(out);
}

}  // namespace des_sim
