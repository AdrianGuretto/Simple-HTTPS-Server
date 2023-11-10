# Simple-HTTPS-Server
A cross-platform HTTPS web server written entirely on C++ for educational purposes.

## Overview
The server utilizes TLS protocol for communicating with the clients connecting to it.

## Project Layout
1. Folder `keys` contains server's certificate, `cert.pem`, and its corresponding private key, `key.pem`.
2. Folder `public` contains all available media for serving clients.

## Dependencies
1. C++17 or higher
2. _OpenSSL_ library, version 3.1.4

## Installation

1. Copy the project folder to your local machine:  
`git clone https://github.com/AdrianGuretto/Simple-HTTPS-Server.git`
2. Go to the project folder:  
`cd Simple-HTTPS-Server`
3. Compile the server code:  
`g++ -std=c++17 https_server.cpp -lcrypto -lssl -o https_server` for _Linux_ or  
 `g++ -std=c++17 https_server.cpp -lcrypto -lssl -o https_server.exe` for _Windows_
4. Launch the server and wait for incoming connections (you can connect from your web browser):  
`https_server 127.0.0.1 8888`