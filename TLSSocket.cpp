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
#include "TLSSocket.h"

#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

TLSSocket::TLSSocket() : _tcpsocket(NULL), _ssl_ca_pem(NULL) {
    // Nothing to do.
}

TLSSocket::TLSSocket(NetworkInterface* net_iface) :  _ssl_ca_pem(NULL) {
        open(net_iface);
}

TLSSocket::~TLSSocket() {
    close();
}

nsapi_error_t TLSSocket::open(NetworkInterface* net_iface) {
    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);
    mbedtls_x509_crt_init(&_cacert);
    mbedtls_ssl_init(&_ssl);
    mbedtls_ssl_config_init(&_ssl_conf);

    _tcpsocket = new TCPSocket();
    _tcpsocket->set_blocking(false);
    
    return _tcpsocket->open(net_iface);
}

nsapi_error_t TLSSocket::close() {
    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);
    mbedtls_x509_crt_free(&_cacert);
    mbedtls_ssl_free(&_ssl);
    mbedtls_ssl_config_free(&_ssl_conf);

    if (_tcpsocket) {
        _tcpsocket->close();
        delete _tcpsocket;
    }

    return 0;
}

void TLSSocket::set_ssl_ca_pem(const char* ssl_ca_pem) {
    _ssl_ca_pem = ssl_ca_pem;
}

nsapi_error_t TLSSocket::connect(const char* hostname, uint16_t port) {
    nsapi_error_t _error = 0;
    const char DRBG_PERS[] = "mbed TLS client";
    const char* _hostname = hostname;
    int _port = port;

    /*
        * Initialize TLS-related stuf.
        */
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                        (const unsigned char *) DRBG_PERS,
                        sizeof (DRBG_PERS))) != 0) {
        print_mbedtls_error("mbedtls_crt_drbg_init", ret);
        _error = ret;
        return _error;
    }

    if ((ret = mbedtls_x509_crt_parse(&_cacert, (unsigned char *)_ssl_ca_pem,
                        strlen(_ssl_ca_pem) + 1)) != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        _error = ret;
        return _error;
    }

    if ((ret = mbedtls_ssl_config_defaults(&_ssl_conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        _error = ret;
        return _error;
    }

    mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
    mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    /* It is possible to disable authentication by passing
        * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
        */
    mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
    mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        _error = ret;
        return _error;
    }

    mbedtls_ssl_set_hostname(&_ssl, _hostname);

    mbedtls_ssl_set_bio(&_ssl, static_cast<void *>(_tcpsocket),
                                ssl_send, ssl_recv, NULL );

    /* Connect to the server */
    mbedtls_printf("Connecting to %s:%d\r\n", _hostname, _port);
    ret = _tcpsocket->connect(_hostname, _port);
    if (ret != NSAPI_ERROR_OK) {
        mbedtls_printf("Failed to connect\r\n");
        _tcpsocket->close();
        return _error;
    }

    /* Start the handshake, the rest will be done in onReceive() */
    mbedtls_printf("Starting the TLS handshake...\n");
    do {
        ret = mbedtls_ssl_handshake(&_ssl);
    } while (ret != 0 && (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        _tcpsocket->close();
        return ret;
    }

    /* It also means the handshake is done, time to print info */
    mbedtls_printf("TLS connection to %s:%d established\r\n", _hostname, _port);

    const uint32_t buf_size = 1024;
    char buf[buf_size] = { 0 };
    mbedtls_x509_crt_info(buf, buf_size, "\r    ",
                    mbedtls_ssl_get_peer_cert(&_ssl));
    mbedtls_printf("Server certificate:\r\n%s\r", buf);

    uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
    if( flags != 0 )
    {
        mbedtls_x509_crt_verify_info(buf, buf_size, "\r  ! ", flags);
        mbedtls_printf("Certificate verification failed:\r\n%s\r\r\n", buf);
    }
    else {
        mbedtls_printf("Certificate verification passed\r\n\r\n");
    }

    return 0;
}

nsapi_error_t TLSSocket::send(const void *data, nsapi_size_t size) {
    int ret = 0;
    unsigned int offset = 0;
    do {
        ret = mbedtls_ssl_write(&_ssl,
                                (const unsigned char *) data + offset,
                                size - offset);
        if (ret > 0)
            offset += ret;
    } while (offset < size && (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        return -1;
    }
    return offset;
}

nsapi_size_or_error_t TLSSocket::recv(void *data, nsapi_size_t size) {
    int ret = 0;
    unsigned int offset = 0;
    do {
        ret = mbedtls_ssl_read(&_ssl, (unsigned char *) data + offset,
                                size - offset);
        if (ret > 0)
            offset += ret;
    } while (((0 < ret && offset < size) || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_read", ret);
        return -1;
    }
    return offset;
}

void TLSSocket::print_mbedtls_error(const char *name, int err) {
    char buf[128];
    mbedtls_strerror(err, buf, sizeof (buf));
    mbedtls_printf("%s() failed: -0x%04x (%d): %s\r\n", name, -err, err, buf);
}


#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0

void TLSSocket::my_debug(void *ctx, int level, const char *file, int line,
                        const char *str)
{
    const char *p, *basename;
    (void) ctx;

    /* Extract basename from file */
    for(p = basename = file; *p != '\0'; p++) {
        if(*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}


int TLSSocket::my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    (void) data;

    mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
    mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
    mbedtls_printf("%s", buf);

    if (*flags == 0)
        mbedtls_printf("No verification issue for this certificate\n");
    else
    {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
        mbedtls_printf("%s\n", buf);
    }

    delete[] buf;
    return 0;
}

#endif /* MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0 */


int TLSSocket::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    int recv = -1;
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    recv = socket->recv(buf, len);

    if(NSAPI_ERROR_WOULD_BLOCK == recv){
        return MBEDTLS_ERR_SSL_WANT_READ;
    }else if(recv < 0){
        mbedtls_printf("Socket recv error %d\n", recv);
        return -1;
    }else{
        return recv;
    }
}

int TLSSocket::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    int size = -1;
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    size = socket->send(buf, len);

    if(NSAPI_ERROR_WOULD_BLOCK == size){
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }else if(size < 0){
        mbedtls_printf("Socket send error %d\n", size);
        return -1;
    }else{
        return size;
    }
}
