# TLSSocket - Brings TLS connection into your mbed app.

This library is created based on [mbed-os-example-tls-tls-client](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-tls-client/) project.

# How to use it
```
TLSSocket socket(network_interface);

// Set root CA certification in PEM format.
socket.set_root_ca_cert( ROOT_CA_CERT_PEM);

// Set client certification and private key
// (optional - for 2-way authentication)
socket.set_client_cert_key( CLIENT_CERT, CLIENT_PRIVATE_KEY);

// Connect to the host
socket.connect( HOST, PORT);

{
  // Do your work
  ..
  socket.send( buf, len);
  ..
  socket.recv( buf, len);
  ..
}

socket.close();
```
# Examples

Please see the example programs.
- [Hello-TLSSocket](https://os.mbed.com/users/coisme/code/Hello-TLSSocket/) HTTP Client with TLS connection.
- [HelloMQTT](https://os.mbed.com/users/coisme/code/HelloMQTT/) MQTT Client with TLS connection.

