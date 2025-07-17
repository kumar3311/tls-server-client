###How to use:

1. Generate server.crt and server.key (self-signed or CA-signed).
2. Generate client.crt and client.key (self-signed or CA-signed).
3. Compile with:
        ```sh
        g++ tls_server.cpp -o tls_server -lssl -lcrypto
        ```
        ```sh
        g++ tls_client.cpp -o tls_client -lssl -lcrypto
        ```
4. Run the server:
        ```sh
        ./tls_server
        ```
5. Run your client:
        ```sh
        tls_client
        ``` 

###1. Create a Root Certificate Authority (CA):
Generate CA Private Key: This key will be used to sign other certificates.
	```sh
    openssl genrsa -out ca.key 2048
	```
Create CA Certificate: This self-signed certificate establishes the CA's identity.
	```sh
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt
	```
###2. Generate Server Certificate:
Generate Server Private Key.
	```sh
    openssl genrsa -out server.key 2048
	```
Create Server Certificate Signing Request (CSR): This request contains information about the server and is signed by the CA.
	```sh
    openssl req -new -key server.key -out server.csr
	```
Sign Server CSR with CA: Use the CA's private key to sign the server's CSR, creating the signed server certificate.
	```sh
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
	```
###3. Generate Client Certificate:
Generate Client Private Key.
	```sh
    openssl genrsa -out client.key 2048
	```
Create Client Certificate Signing Request (CSR).
	```sh
    openssl req -new -key client.key -out client.csr
	```
Sign Client CSR with CA.
	```sh
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
	```
###4. C++ Client-Server Program Integration:

###Server-side:
The server program will need to load server.key (private key) and server.crt (signed certificate) to establish its identity. It also needs ca.crt to verify client certificates if mutual TLS (mTLS) is used.

###Client-side:
The client program will need to load client.key and client.crt for client authentication (if mTLS is used). It also needs ca.crt to verify the server's certificate.

# tls-server-client
