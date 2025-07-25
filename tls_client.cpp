#include "tls_imp.hpp"

const std::string SERVER_ADDR = "xx.xx.xx.xx"; // Replace with the actual server address
// const std::string SERVER_ADDR = "127.0.0.1"; // For local testing
const int SERVER_PORT = 3336;
const std::string CERT_FILE = "certs/client.crt";
const std::string KEY_FILE = "certs/client.key";

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    // Use TLSv1.2 only
    SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed\n";
        return 1;
    }
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load cert/key\n";
        SSL_CTX_free(ctx);
        return 1;
    }
    // Check if cert and key are valid
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Certificate and private key do not match or are invalid\n";
        SSL_CTX_free(ctx);
        return 1;
    }
    // Check if certificate is expired
    X509* cert = nullptr;
    FILE* fp = fopen(CERT_FILE.c_str(), "r");
    if (fp) {
        cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        fclose(fp);
    }
    if (!cert) {
        std::cerr << "Failed to read certificate for expiry check\n";
        SSL_CTX_free(ctx);
        return 1;
    }
    if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
        std::cerr << "Certificate is not yet valid\n";
        X509_free(cert);
        SSL_CTX_free(ctx);
        return 1;
    }
    if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
        std::cerr << "Certificate is expired\n";
        X509_free(cert);
        SSL_CTX_free(ctx);
        return 1;
    }
    X509_free(cert);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set source port to 3336
    sockaddr_in src_addr{};
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(SERVER_PORT); // source port
    src_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&src_addr, sizeof(src_addr)) != 0) {
        std::cerr << "Failed to bind source port\n";
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    struct hostent* host = gethostbyname(SERVER_ADDR.c_str());
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr = *(struct in_addr*)host->h_addr;

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "Connection failed\n";
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL_connect failed\n";
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::string authdata;
    unsigned long pov_count = 0;
    while (true) {
        std::string line = ssl_readline(ssl);
        if (line.empty()) 
        { 
            std::cout << "no data received from server, waiting..." << std::endl;
            ssl_writeline(ssl, "HELO\n");
            std::cout << "send HELO command to server" << std::endl;
            continue;
            
        }

        auto args = split(line);

        if (args.empty()) continue;
        if (args[0] == "HELO") {
            ssl_writeline(ssl, "TOAKUEI\n");
        } else if (args[0] == "ERROR") {
            std::cerr << "ERROR: ";
            for (size_t i = 1; i < args.size(); ++i) std::cerr << args[i] << " ";
            std::cerr << std::endl;
            break;
        } else if (args[0] == "POW") {
            authdata = args[1];
            int difficulty = std::stoi(args[2]);
            std::string zeros(difficulty, '0');
            std::atomic<bool> found(false);
            std::string result_suffix;
            std::mutex result_mutex;
            unsigned long pov_count = 0;
            int length = authdata.length(); // 8 is the length of the random suffix
            const int num_threads = std::thread::hardware_concurrency();
            std::vector<std::thread> workers;
            std::cout << " num_threads :" << num_threads << "  difficulty: " << difficulty<< std::endl;

            for (int t = 0; t < num_threads; ++t) {
                workers.emplace_back([&, t]() {
                    while (!found.load(std::memory_order_relaxed)) {
                        std::string suffix = random_string( t + 1 );
                        std::string cksum = sha1_hex(authdata + suffix);
                       
                       if(hasTwoOrMoreZeroPrefix(cksum)) {
                            pov_count++;
                            std::cout << " authdata + suffix: " << authdata + " <---> " + suffix << "  --> cksum :" <<cksum <<"  pov_count: " << pov_count << "\t\r"<< std::flush;
                        }

                        if (cksum.substr(0, difficulty) == zeros) {
                            std::lock_guard<std::mutex> lock(result_mutex);
                            if (!found) {
                                found = true;
                                result_suffix = suffix;
                            }
                            break;
                        }
                    }
                });
            }
            //std::cout << "end of threads creation" << std::endl;
            std::cout << "Number of threads: " << num_threads << std::endl;
            for (auto& th : workers) th.join();
            ssl_writeline(ssl, result_suffix + "\n");
        } else if (args[0] == "END") {
            ssl_writeline(ssl, "OK\n");
            break;
        } else if (args[0] == "NAME") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " " + "xxxxx xxxxx xxxxxxx\n");
        } else if (args[0] == "MAILNUM") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " 2\n");
        } else if (args[0] == "MAIL1") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " xxxxxxxxxxxxxxxx@gmail.com\n");
        } else if (args[0] == "MAIL2") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " xxxxxxxxxxxxxxxx@hotmail.com\n");
        } else if (args[0] == "SKYPE") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " xxxxxxxxxxxxxxxx@hotmail.com\n");
        } else if (args[0] == "BIRTHDATE") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " dd.mm.yyyy\n");
        } else if (args[0] == "COUNTRY") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " India\n");
        } else if (args[0] == "ADDRNUM") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " 2\n");
        } else if (args[0] == "ADDRLINE1") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " dd, xxddddxxx dddddd\n");
        } else if (args[0] == "ADDRLINE2") {
            ssl_writeline(ssl, sha1_hex(authdata + args[1]) + " xxxxxxxxx, xxxxxxxxx-xxxxxx\n");
        }
    }

    std::cout << " closing tls client connection " << std::endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}