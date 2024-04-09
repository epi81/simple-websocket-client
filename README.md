# simple-websocket-client
a simple prototype of ssl websocket client written in c

HOST/PATH/PORT is hardcoded.

It tested with local Ratchet secure server.
I dont know why cannot connect to echo.websocket.org,

* OpenSSL is used to establish a TLS/SSL connection.

* Attempt SSL handshake with different TLS versions

# compile
just run make

# references:
[rfc6455]https://www.rfc-editor.org/rfc/rfc6455#section-5.4
