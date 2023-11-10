#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif


#if defined(_WIN32)
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

#else
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)
#endif


#include <iostream>
#include <cstring>
#include <string>
#include <time.h>
#include <filesystem>
#include <unordered_map>
#include <fstream>
#include <csignal>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_WRITE_BUFFER_LEN 2048

bool EXIT_FLAG = false;

using namespace std::string_literals;

enum class Color{
    Red = 0,
    Green = 1,
    Yellow = 2,
    Pink = 3,
    Cyan = 4,
};

// Make a colored string using ANSI espace sequences
inline static std::string MakeColorfulText(std::string&& text, Color color){
    const std::unordered_map<Color, std::string> color_to_ansi_seq = {{Color::Red, "\u001b[31m"s}, {Color::Green, "\u001b[32m"s}, {Color::Yellow, "\u001b[33m"s}, {Color::Pink, "\u001b[35m"s}, {Color::Cyan, "\u001b[36m"s}};
    std::string reset_seq = "\u001b[0m"; // to limit text coloring to only our text chunk.
    std::string ret_str;
    ret_str.reserve(text.size() + 2);
    ret_str += color_to_ansi_seq.at(color);
    ret_str.append(std::move(text));
    ret_str += reset_seq;
    return ret_str;
}

static void SignalHandler(int signal_num){
    EXIT_FLAG = true;
}

inline static std::string GetTimestamp(){
    const std::time_t now = std::time(nullptr);
    char time_string[100];
    std::strftime(time_string, sizeof(time_string), "%d %b %Y %H:%M:%S", std::localtime(&now));

    std::string ret_str("["s + std::string(time_string) + "]"s);

    return ret_str;
}

inline static std::string GetSSLErrorString(){
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buff = nullptr;
    size_t err_len = BIO_get_mem_data(bio, &buff);
    std::string err_str(buff, err_len);
    BIO_free(bio);
    return err_str;
}

class Logger{
public:
    explicit Logger(std::string&& logger_name) : logger_name_(std::move(logger_name)) {}

    void Info(std::string&& message) const noexcept{
        std::string final_msg = GetTimestamp() + "-["s + logger_name_  + "]-[INFO] "s + std::move(message);
        std::cerr << MakeColorfulText(std::move(final_msg), Color::Cyan) << '\n';
    }

    void Debug(std::string&& message) const noexcept{
        std::string final_msg = GetTimestamp() + "-["s + logger_name_  + "]-[DEBUG] "s + std::move(message);
        std::cerr << MakeColorfulText(std::move(final_msg), Color::Yellow) << '\n';
    }

    void Error(std::string&& message) const noexcept{
        std::string final_msg = GetTimestamp() + "-["s + logger_name_  + "]-[ERROR] "s + std::move(message);
        std::cerr << MakeColorfulText(std::move(final_msg), Color::Red) << '\n';
    }

    void Warning(std::string&& message) const noexcept{
        std::string final_msg = GetTimestamp() + "-["s + logger_name_ + "]-[WARNING] "s + std::move(message);
        std::cerr << MakeColorfulText(std::move(final_msg), Color::Pink) << '\n';
    }
private:
    const std::string logger_name_;
};

inline static void InitSSLLib(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

inline static std::string GetAddressString(sockaddr_storage* conn_address){
    char address[INET6_ADDRSTRLEN];

    int port = 0;

    if (conn_address->ss_family == AF_INET) { // IPv4
        sockaddr_in* addr_inf = reinterpret_cast<sockaddr_in*>(conn_address);
        inet_ntop(AF_INET, &addr_inf->sin_addr, address, INET_ADDRSTRLEN);
        port = ntohs(addr_inf->sin_port);
    } else if (conn_address->ss_family == AF_INET6) { // IPv6
        sockaddr_in6* addr_inf = reinterpret_cast<sockaddr_in6*>(conn_address);
        inet_ntop(AF_INET6, &addr_inf->sin6_addr, address, INET6_ADDRSTRLEN);
        port = ntohs(addr_inf->sin6_port);
    }
    std::string conn_info(address);
    conn_info += ':';
    conn_info.append(std::to_string(port));
    
    return conn_info;
}

inline static std::string GetResourceType(std::filesystem::path& file_path){
    const static std::unordered_map<std::string, std::string> extentions_to_mime_format = {
        {".css"s, "text/css"s},
        {".csv"s, "text/csv"s},
        {".gif"s, "image/gif"s},
        {".htm"s, "text/html"s},
        {".html"s, "text/html"s},
        {".ico"s, "image/x-icon"s},
        {".jpeg"s, "text/jpeg"s},
        {".jpg"s, "text/jpeg"s},
        {".js"s, "application/javascript"s},
        {".json"s, "application/json"s},
        {".pdf"s, "application/pdf"s},
        {".svg"s, "image/svg+xml"s},
        {".txt"s, "text/plain"s},
    };

    std::string file_name(file_path.filename().string());
    std::string file_extention = file_name.substr(file_name.find('.'));
    
    return extentions_to_mime_format.count(file_extention) ? extentions_to_mime_format.at(file_extention) : "application/octet-stream"s;
}

struct ClientInfo{
    socklen_t address_len;
    sockaddr_storage address;
    std::string address_string;
    SOCKET socketfd;
    SSL* ssl = nullptr;
    char write_buffer[MAX_WRITE_BUFFER_LEN + 1]; // + 1 for null-terminating character
    int received_bytes = 0;
};

class HTTPS_Server{
public:
    explicit HTTPS_Server(const char* hostname, const char* port);

    HTTPS_Server(const HTTPS_Server& other) = delete;
    HTTPS_Server& operator=(const HTTPS_Server& other) = delete;

    ~HTTPS_Server();

public:
    int Start() noexcept;

    void Shutdown() noexcept;

private:

    SOCKET CreateServerSocket() noexcept;

    /* Associate the server with a certificate and a private key
     * @return -1 on error, 0 on success.
    */
    int InitServerSSLContext() noexcept;

    void RemoveClient(SOCKET client_socketfd) noexcept;

    /* Established TLS connection with `client`.
     * @return -1 on error, 0 on success.
    */
    int EstablishNewSSLConnection(ClientInfo* client);

    /* Accepts new connection with `accept()` and fills `client_holder` with new client information.
     * @return -2 on failed connection, -1 on exceeded connection fail cap, 0 on success.
    */
    int AcceptNewClient() noexcept;

    /* Handle actively connected clients.
     * @return -1 on error, 0 on successful exit.
    */
    int HandleActiveClients() noexcept;

    void Send400Error(ClientInfo& client) noexcept;
    void Send404Error(ClientInfo& client) noexcept;

    /* Sends a resource at `resource_path` to `client`.
     * @return -1 on error with `errno` set, 0 on success.
    */
    int ServeResource(ClientInfo& client, std::filesystem::path resource_path) noexcept;

    /* Read data from client's SSL connection and write it to client's buffer.
     * @return -1 on socket error, 0 on client disconnect, 1 on success.
    */
    int ReceiveData(ClientInfo* client) noexcept;

    int SendData(ClientInfo* client, const std::string& message_buffer) noexcept;
    int SendData(ClientInfo* client, const char* message_buffer, const size_t bytes_to_send = 0) noexcept;

private:
    const char* hostname_str_, *port_str_;
    SOCKET server_socket_;
    SSL_CTX* server_SSL_context_ = nullptr;
    Logger logger_;

    fd_set sockets_polling_set_;
    SOCKET max_socket_;

    std::unordered_map<SOCKET, ClientInfo> socketfd_to_client_;
};

HTTPS_Server::HTTPS_Server(const char* hostname, const char* port) : hostname_str_(hostname), port_str_(port), logger_("HTTPS_SERVER") {}

HTTPS_Server::~HTTPS_Server(){
    Shutdown();
}

int HTTPS_Server::Start() noexcept{
    logger_.Info("Starting the server..."s);
    
    server_socket_ = CreateServerSocket();
    if (InitServerSSLContext() == -1){
        return -1;
    }

    FD_ZERO(&sockets_polling_set_);
    FD_SET(server_socket_, &sockets_polling_set_);

    max_socket_ = server_socket_;
    if (!ISVALIDSOCKET(server_socket_)){
        return -1;
    }

    return HandleActiveClients();
}

void HTTPS_Server::Shutdown() noexcept{
    logger_.Info("Shutting down the server..."s);
    for (auto& [sock, client] : socketfd_to_client_){
        SSL_shutdown(client.ssl);
        CLOSESOCKET(client.socketfd);
        SSL_free(client.ssl);
    }
    CLOSESOCKET(server_socket_);
    SSL_CTX_free(server_SSL_context_);
    logger_.Info("Server is offline."s);
}

int HTTPS_Server::InitServerSSLContext() noexcept{
    server_SSL_context_ = SSL_CTX_new(TLS_server_method());
    if (!server_SSL_context_){
        logger_.Error("Failed to create server SSL context: SSL_CTX_new(): "s + GetSSLErrorString());
        return -1;
    }

    // Try to use the server certificate and associated private key
    if (!SSL_CTX_use_certificate_file(server_SSL_context_, std::filesystem::path("keys/cert.pem").string().data(), SSL_FILETYPE_PEM)
    ||  !SSL_CTX_use_PrivateKey_file(server_SSL_context_, std::filesystem::path("keys/key.pem").string().data(), SSL_FILETYPE_PEM)){
        logger_.Error("SSL_CTX_use_certificate_file() failed: "s + GetSSLErrorString());
        return -1;
    }
    return 0;
}

SOCKET HTTPS_Server::CreateServerSocket() noexcept{
    addrinfo hints, *bind_addr;
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    logger_.Debug("Configuring server's address..."s);
    if (getaddrinfo(hostname_str_, port_str_, &hints, &bind_addr) != 0){
        logger_.Error("[!] Failed to configure server's address: getaddrinfo(): "s + std::system_category().message(GETSOCKETERRNO()));
        return -1;
    }

    logger_.Debug("Creating server socket..."s);
    SOCKET server_socket = socket(bind_addr->ai_family, bind_addr->ai_socktype, bind_addr->ai_protocol);
    if (!ISVALIDSOCKET(server_socket)){
        logger_.Error("Failed to create server's socket: socket(): "s + std::system_category().message(GETSOCKETERRNO()));
        return -1;
    }

    logger_.Debug("Configuring server's socket..."s);
    int yes = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1){
        logger_.Error("Failed to configure server's socket: setsockopt(): "s + std::system_category().message(GETSOCKETERRNO()));
        return -1;
    }

    std::string server_addr_str(GetAddressString(reinterpret_cast<sockaddr_storage*>(bind_addr->ai_addr)));

    logger_.Debug("Bind server to address "s + server_addr_str);
    if (bind(server_socket, bind_addr->ai_addr, bind_addr->ai_addrlen) == -1){
        logger_.Error("Failed to bind server to "s + server_addr_str + " : bind(): "s + std::system_category().message(GETSOCKETERRNO()));
        return -1;
    }
    freeaddrinfo(bind_addr);

    if (listen(server_socket, 10) == -1){
        logger_.Error("Failed to enable server listenning mdoe: listen(): "s + std::system_category().message(GETSOCKETERRNO()));
        return -1;
    }

    logger_.Info("Listenning for incoming connections on "s + server_addr_str);
    return server_socket;
}

void HTTPS_Server::RemoveClient(SOCKET client_socketfd) noexcept{
    if (!socketfd_to_client_.count(client_socketfd)){
        logger_.Warning("Failed to disconnect client with socketfd "s + std::to_string(client_socketfd) + ": socket is not connected."s);
        return;
    }

    ClientInfo& client = socketfd_to_client_.at(client_socketfd);
    SSL_shutdown(client.ssl);
    FD_CLR(client_socketfd, &sockets_polling_set_);
    CLOSESOCKET(client_socketfd);
    SSL_free(client.ssl);

    logger_.Info("Client "s + client.address_string + " has been disconnected."s);
    socketfd_to_client_.erase(client_socketfd);
}

int HTTPS_Server::EstablishNewSSLConnection(ClientInfo* client){
    logger_.Info("Establishing TLS connection with "s + client->address_string);

    if (!(client->ssl = SSL_new(server_SSL_context_))){
        logger_.Warning("Failed to establish TLS connection with "s + client->address_string + " : SSL_new(): "s + GetSSLErrorString());
        return -1;
    }
    

    // Bind client socket to the newly SSL connection
    if (SSL_set_fd(client->ssl, client->socketfd) == -1){
        logger_.Warning("Failed to establish TLS connection with "s + client->address_string + ". "s + GetSSLErrorString());
        return -1;
    }

    if (SSL_accept(client->ssl) != 1){
        logger_.Warning("Failed to establish TLS connection with "s + client->address_string + ". "s + GetSSLErrorString());
        return -1;
    }

    logger_.Info("Successfully established TLS connection with "s + client->address_string);
    
    return 0;
}

int HTTPS_Server::AcceptNewClient() noexcept{
    ClientInfo new_client;
    new_client.socketfd = accept(server_socket_, reinterpret_cast<sockaddr*>(&new_client.address), &new_client.address_len);
    new_client.address_string = GetAddressString(&new_client.address); // Write the connection address of the new client
    logger_.Info("New connection from "s + new_client.address_string);

    static int conn_accept_errors = 0;

    if (!ISVALIDSOCKET(new_client.socketfd)){
        logger_.Warning("Failed to accept new connection from "s + new_client.address_string + " : accept()"s + std::system_category().message(GETSOCKETERRNO()));
        if (conn_accept_errors >= 5){
            logger_.Error("Exceeded failed connections cap of 5. Shutting down the server..."s);
            return -1;
        }
        return -2;
    }

    if (EstablishNewSSLConnection(&new_client) == -1){
        return -1;
    }

    if (new_client.socketfd > max_socket_){
        max_socket_ = new_client.socketfd;
    }
    FD_SET(new_client.socketfd, &sockets_polling_set_);

    socketfd_to_client_[new_client.socketfd] = std::move(new_client);
    return 1;
}

int HTTPS_Server::SendData(ClientInfo* client, const std::string& message_buff) noexcept{
    int total_bytes = message_buff.size();
    int sent_bytes = 0;
    int tmp_var; 

    logger_.Debug("Sending "s + std::to_string(total_bytes) + " bytes to "s + client->address_string);

    while (sent_bytes < total_bytes){
        tmp_var = SSL_write(client->ssl, message_buff.data() + sent_bytes, total_bytes - sent_bytes);
        if (tmp_var == -1){
            logger_.Warning("Failed to sent data to "s + client->address_string + " : SSL_write(): "s + std::system_category().message(GETSOCKETERRNO()));
            return -1;
        }
        sent_bytes += tmp_var;
    }

    return 1;
}
int HTTPS_Server::SendData(ClientInfo* client, const char* message_buff, const size_t bytes_to_send) noexcept{
    int total_bytes = bytes_to_send == 0 ? strlen(message_buff) : bytes_to_send;
    int sent_bytes = 0;
    int tmp_var; 

    logger_.Debug("Sending "s + std::to_string(total_bytes) + " bytes to "s + client->address_string);

    while (sent_bytes < total_bytes){
        tmp_var = SSL_write(client->ssl, message_buff + sent_bytes, total_bytes - sent_bytes);
        if (tmp_var == -1){
            logger_.Warning("Failed to sent data to "s + client->address_string + " : SSL_write(): "s + std::system_category().message(GETSOCKETERRNO()));
            return -1;
        }
        sent_bytes += tmp_var;
    }

    return 1;
}

int HTTPS_Server::ReceiveData(ClientInfo* client) noexcept{
    if (client->received_bytes >= MAX_WRITE_BUFFER_LEN){
        logger_.Warning("Failed to receive data from "s + client->address_string + " : Data buffer size exceeded."s);
        return -1;
    }
    int read_bytes = SSL_read(client->ssl, client->write_buffer + client->received_bytes, MAX_WRITE_BUFFER_LEN - client->received_bytes);
    if (read_bytes <= 0){
        if (read_bytes == -1){
            logger_.Error("Failed to receive data from "s + client->address_string + " : recv(): "s + std::system_category().message(GETSOCKETERRNO()));
            int tmp = errno;
            logger_.Error("errno: "s + std::to_string(tmp) + std::string(strerror(errno)));
        }
        return read_bytes;
    }
    client->received_bytes += read_bytes;
    logger_.Debug("Received "s + std::to_string(read_bytes) + " bytes from "s + client->address_string);
    return 1;
}

void HTTPS_Server::Send400Error(ClientInfo& client) noexcept{
// clang-format off
    std::string err_msg_string =
    "HTTP/1.1 400 Bad Request\r\n"s
    "Connection: close\r\n"s
    "Content-Length: 11\r\n\r\nBad Request"s;
// clang-format on
    SendData(&client, err_msg_string);
    RemoveClient(client.socketfd);
}
void HTTPS_Server::Send404Error(ClientInfo& client) noexcept{
// clang-format off
    std::string err_msg_string =
    "HTTP/1.1 404 Not Found\r\n"s
    "Connection: close\r\n"s
    "Content-Length: 9\r\n\r\nNot Found"s;
// clang-format on
    SendData(&client, err_msg_string);
    RemoveClient(client.socketfd);
}

int HTTPS_Server::ServeResource(ClientInfo& client, std::filesystem::path resource_path) noexcept{
    if (resource_path == std::filesystem::path("/")){
        resource_path = std::filesystem::path("/index.html");
    }

    logger_.Info("Serving \""s + resource_path.string() + "\" to client "s + client.address_string);

    std::ifstream in_file(resource_path, std::ios::binary);
    if (!in_file.is_open()){
        logger_.Error("Failed to open file at \""s + resource_path.string() + "\""s);
        return -1;
    }

    const size_t file_size = std::filesystem::file_size(resource_path);
    const std::string content_type = GetResourceType(resource_path);

// clang-format off
    std::string resp_str = 
    "HTTP/1.1 200 OK\r\n"s
    "Connection: keep-alive\r\n"s
    "Content-Length: "s + std::to_string(file_size) + "\r\n"s
    "Content-Type: "s + content_type + "\r\n\r\n"s;
// clang-format on

    if (SendData(&client, resp_str) == -1){
        return -1;
    }

    char file_buffer[2048];
    while (in_file.read(file_buffer, sizeof(file_buffer))){
        if (SendData(&client, file_buffer, in_file.gcount()) == -1){
            return -1;
        }
    }

    // Check for any remaining data in the file buffer
    if (in_file.gcount() > 0){
        if (SendData(&client, file_buffer, in_file.gcount()) == -1){
            return -1;
        }
    }

    bzero(client.write_buffer, sizeof(client.write_buffer));
    client.received_bytes = 0;
    return 0;
}


int HTTPS_Server::HandleActiveClients() noexcept{
    while (!EXIT_FLAG){
        fd_set reads_copy;
        FD_COPY(&sockets_polling_set_, &reads_copy); // Since select() modifies the fd_set

        if (select(max_socket_ + 1, &reads_copy, 0, 0, 0) == -1){
            logger_.Error("Failed to read data from active connections: select(): "s + std::system_category().message(GETSOCKETERRNO()));
            return -1;
        }

        for (SOCKET sock = 0; sock <= max_socket_; ++sock){
            if (FD_ISSET(sock, &reads_copy)){
                if (sock == server_socket_){ // new data on the server socket == new connection has arrived
                    int new_conn_status = AcceptNewClient();
                    if (new_conn_status <= -1){
                        if (new_conn_status == -1){
                            continue;
                        }
                        else if (new_conn_status == -2){
                            return -1;
                        }
                    }
                }
                else{ // Regular client sending us data
                    ClientInfo& client = socketfd_to_client_.at(sock);
                    int recv_bytes = ReceiveData(&client);
                    if (recv_bytes <= 0){
                        // if (recv_bytes == -1){ // if recv() returns -1, it mean a trouble with the server.
                        //     return -1;
                        // }
                        RemoveClient(client.socketfd);
                    }

                    char* client_req_end = strstr(client.write_buffer, "\r\n\r\n");
                    if (client_req_end){ // upon receiving the entire client request...
                        *client_req_end = 0x00; // null-terminate the end of the write buffer.
                        if (strncmp("GET /", client.write_buffer, 5)){
                            Send400Error(client); // The server only supports GET requests
                            continue;
                        }
                        char* path_begin_ptr = client.write_buffer + 4;
                        char* path_end_ptr = strstr(path_begin_ptr, " ");
                        if (!path_end_ptr){
                            Send400Error(client);
                            continue;
                        }

                        // Check if the requested path is valid
                        *path_end_ptr = 0x00;
                        std::string path_str(path_begin_ptr);
                        if (path_str.find(".."s) != path_str.npos){ // forbid root directory access
                            Send404Error(client);
                            continue;
                        }
                        
                        std::filesystem::path req_path("public" + path_str);

                        if (!std::filesystem::exists(req_path)){ // requested path not found
                            Send404Error(client);
                            continue;
                        }

                        if (ServeResource(client, (path_str == "/" ? std::filesystem::path("public/index.html") : req_path)) == -1){
                            RemoveClient(client.socketfd);
                        }
                    } // if (client_req_end)
                } // else (regular client sending data)
            } // if (FD_ISSET)
        } // for (sockets in reads)
    } // while (!EXIT_FLAG)
    return 0;
}



int main(int argc, char* argv[]){
    if (argc != 3){
        std::cerr << "[Usage] https_server <hostname> <port>"s << std::endl;
        return 1;
    }
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)){
        std::cerr << "Failed to initialize WinSockAPI: "s << std::system_category().message() << std::endl;
        return 1;
    }
#endif
    std::signal(SIGINT, SignalHandler); // Handle interrupt call (CTRL + C)

    InitSSLLib();
    HTTPS_Server server(argv[1], argv[2]);
    if (server.Start() == -1){
        return 1;
    }
}