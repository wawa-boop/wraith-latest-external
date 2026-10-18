#pragma once
#include <vector>
#include <cstdint>
#include <string>
namespace wraith {
std::vector<uint8_t> crypt(const std::vector<uint8_t>& in, const std::string& key);
}
