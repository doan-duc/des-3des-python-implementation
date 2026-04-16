#pragma once

#include "../DataTypes/Key_types.hpp"

#include <cstdint>
#include <tuple>
#include <vector>

using namespace std;

namespace des_sim {
vector<uint64_t> generate_subkeys_from_deskey(const DESKey& des_key, bool verbose = false);
tuple<vector<uint64_t>, vector<uint64_t>, vector<uint64_t>, double> generate_all_3des_subkeys(
    const TripleDESKey& triple_key, bool verbose = false
);
}
