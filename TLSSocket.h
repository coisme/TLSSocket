/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MBED_HTTPS_TLS_SOCKET_H_
#define _MBED_HTTPS_TLS_SOCKET_H_

#include "TCPSocket.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


/**
 * \brief TLSSocket a wrapper around TCPSocket for interacting with TLS servers
 */
class TLSSocket {
public:
    /* Create an uninitialized socket.
     *
     * Must call open to initialize the socket on a network stack.
     */
    TLSSocket();

    /** Create a socket on a network interface
     *
     *  Creates and opens a socket on the network stack of the given
     *  network interface.
     *
     *  @param net_iface    Network stack as target for socket
     */
    TLSSocket(NetworkInterface* net_iface);

    /** Destroy a socket
     *
     *  Closes socket if the socket is still open
     */
    ~TLSSocket();

    /** Connects TLS socket to a remote host
     *
     *  Initiates a connection to a remote server specified by either
     *  a domain name or an IP address and a port.
     *
     *  @param host     Hostname of the remote host
     *  @param port     Port of the remote host
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t open(NetworkInterface* net_iface);

    /** Close the socket
     *
     *  Closes any open connection and deallocates any memory associated
     *  with the socket. Called from destructor if socket is not closed.
     *
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t close();

    /** Sets the certification of Root CA.
     *
     * @param Root CA Certification in PEM format
     */
    void set_ssl_ca_pem(const char* ssl_ca_pem);

    /** Connects TLS socket to a remote host
     *
     *  Initiates a connection to a remote server specified by either
     *  a domain name or an IP address and a port.
     * 
     *  Root CA certification must be set by set_ssl_ca_pem() before
     *  call this function.
     *
     *  @param host     Hostname of the remote host
     *  @param port     Port of the remote host
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t connect(const char* hostname, uint16_t port);

    /** Send data over a TLS socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes sent from the buffer.
     *
     *  @param data     Buffer of data to send to the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of sent bytes on success, negative error
     *                  code on failure
     */
    nsapi_error_t send(const void *data, nsapi_size_t size);

    /** Receive data over a TLS socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes received into the buffer.
     *
     *  @param data     Destination buffer for data received from the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of received bytes on success, negative error
     *                  code on failure. If no data is available to be received
     *                  and the peer has performed an orderly shutdown,
     *                  recv() returns 0.
     */
    nsapi_size_or_error_t recv(void *data, nsapi_size_t size);

protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err);

#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                        const char *str);

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

#endif /* MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0 */

    /**
     * Receive callback for Mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Send callback for Mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

private:
    TCPSocket* _tcpsocket;
    const char* _ssl_ca_pem;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _ssl_conf;
};

#endif // _MBED_HTTPS_TLS_SOCKET_H_
