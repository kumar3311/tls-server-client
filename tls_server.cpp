#include "tls_imp.hpp"

const int PORT = 3336;
const std::string CERT_FILE = "certs/server.crt";
const std::string KEY_FILE = "certs/server.key";
static int bGotDifficulty = 0; 
static int next_cmd = 0;
std::vector<std::string> cmd{"HELO", "POW", "NAME", "MAILNUM", "MAIL1", "MAIL2", "SKYPE", "BIRTHDATE", "COUNTRY", "END"};

void setTimeOut(int mins, int client_fd, SSL* ssl) {
    // Introduce timeout before reading from client
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(client_fd, &readfds);
    struct timeval tv;
    tv.tv_sec = mins * 60; // seconds
    tv.tv_usec = 0;
    int sel_ret = select(client_fd + 1, &readfds, nullptr, nullptr, &tv);
    if (sel_ret == 0) {
        std::cerr << "Timeout: no client data received in 2 hours\n";
        ssl_writeline(ssl, "ERROR Timeout\n");
        return;
    } else if (sel_ret < 0) {
        std::cerr << "Select error\n";
        ssl_writeline(ssl, "ERROR Select\n");
        return;
    }
}
void sendCmd( std::vector<std::string> &cmds, SSL* ssl, int client_fd, std::string &authdata, int &difficulty) {
    if (next_cmd < cmds.size()) {
        
        std::cout << "Sending command: " << cmds[next_cmd] << std::endl;
        ssl_writeline(ssl, cmds[next_cmd] + " " + authdata + " " + std::to_string(difficulty) + "\n");
        if (cmds[next_cmd] == "POW") {
            // Generate random authdata for POW
            std::string authdata = random_string();
            int difficulty = 6; // or any value you want
            setTimeOut(2 * 60, client_fd, ssl); // 2 hours timeout                       
        } else if (cmds[next_cmd] != "END") {
            setTimeOut(10, client_fd, ssl); // 10 Min timeout                        
        }
                
    } else {
        ssl_writeline(ssl, "END\n");
        std::cout << "Sent: END" << std::endl;
    }
    
    next_cmd++;
}
std::string send_command_and_wait(const std::string& command, SSL* ssl, int client_fd, int timeout_minutes = 10) {
    ssl_writeline(ssl, command + "\n");
    std::cout << "Sent: " << command << std::endl;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(client_fd, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_minutes * 60;
    tv.tv_usec = 0;
    int sel_ret = select(client_fd + 1, &readfds, nullptr, nullptr, &tv);
    if (sel_ret == 0) {
        std::cerr << "Timeout: no client data received\n";
        ssl_writeline(ssl, "ERROR Timeout\n");
        return "";
    } else if (sel_ret < 0) {
        std::cerr << "Select error\n";
        ssl_writeline(ssl, "ERROR Select\n");
        return "";
    }
    std::string response = ssl_readline(ssl);
    std::cout << "Received: " << response << std::endl;
    return response;
}
int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
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

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Bind failed\n";
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    listen(server_fd, 1);

    std::cout << "Server listening on port " << PORT << std::endl;

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        std::cerr << "Accept failed\n";
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL_accept failed\n";
        SSL_free(ssl);
        close(client_fd);
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
     
    unsigned  long pow_count = 0;
    int difficulty = 6;//6;//9; // or any value you want
    std::string authdata = random_string();
    while (true) {
        sendCmd(cmd, ssl, client_fd, authdata, difficulty);
        std::string line = ssl_readline(ssl);
        if (line.empty()) break;
        auto args = split(line);
        if (args.empty()) continue;
        if( args[0] == "OK") {
            std::cout << "Receved response:  " << args[0] << std::endl;
            break;
        }
        else if ( args.size() == 1 && cmd[next_cmd - 1] == "POW") {
            std::cout << "Received response:  " << args[0] << std::endl;            
        }
        else if( args[0] == "TOAKUEI") {
            std::cout << "Receved response:  " << args[0] << std::endl;
            continue;
        }
        else {
            std::cout << "Received response:  " << args[0] << " " << args[1]<< std::endl;
        }        
    } 

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}