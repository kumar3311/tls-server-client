#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <random>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#include <unistd.h>
#include <iomanip>
#include <sys/types.h>
#include <cstring>
#include <mutex>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <iomanip>
#include <stdexcept>
#include <set>
#include "utf8utils.hpp"
#include <cstdint>


// Function prototypes start 
bool hasTwoOrMoreZeroPrefix(const std::string& str);
std::vector<std::string> split(const std::string& s);
std::string sha1_hex(const std::string& input);
std::string random_string(size_t length);
void ssl_writeline(SSL* ssl, const std::string& line);
std::string ssl_readline(SSL* ssl);

// Funtion definitions start

bool hasTwoOrMoreZeroPrefix(const std::string& str) {
    return str.rfind("000000", 0) == 0;
}

std::vector<std::string> split(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> result;
    std::string item;
    while (iss >> item) result.push_back(item);
    return result;
}

// Helper: SHA1 hex digest
std::string sha1_hex(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// Helper: generate random string (UTF-8 safe, no \n, \r, \t, space)
std::string random_string(size_t length = 8) {
    // Only use printable ASCII characters for UTF-8 compatibility
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    static std::mt19937 rng{std::random_device{}()};
    static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string str;
    while (str.size() < length) {
        char c = charset[dist(rng)];
        if (c != '\n' && c != '\r' && c != '\t' && c != ' ')
            str += c;
    }
    return str;
}

// Helper: read a line from SSL
std::string ssl_readline(SSL* ssl) {
    std::string line;
    char c;
    while (SSL_read(ssl, &c, 1) == 1 && c != '\n') {
        if (c != '\r') line += c;
    }
    return line;
}

// Helper: write a line to SSL
void ssl_writeline(SSL* ssl, const std::string& line) {
    SSL_write(ssl, line.c_str(), line.size());
}

