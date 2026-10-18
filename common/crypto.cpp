#include "crypto.h"
namespace wraith {
std::vector<uint8_t> crypt(const std::vector<uint8_t>& in, const std::string& key) {
    std::vector<uint8_t> out(in.size());
    uint8_t k = 0;
    for (size_t i = 0; i < in.size(); i++) {
        k = (uint8_t)((k + (unsigned char)key[i % key.size()]) & 0xFF);
        out[i] = in[i] ^ k;
    }
    return out;
}
}
