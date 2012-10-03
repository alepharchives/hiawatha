/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "config.h"

#ifdef ENABLE_SSL

#define ENABLE_DEBUG_LEVEL   0
#define TIMESTAMP_SIZE      40

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "alternative.h"
#include "libssl.h"
#include "log.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"

static int ciphersuites[] = {
	SSL_EDH_RSA_AES_256_SHA,
	SSL_EDH_RSA_CAMELLIA_256_SHA,
	SSL_EDH_RSA_AES_128_SHA,
	SSL_EDH_RSA_CAMELLIA_128_SHA,
	SSL_EDH_RSA_DES_168_SHA,
	SSL_RSA_AES_256_SHA,
	SSL_RSA_CAMELLIA_256_SHA,
	SSL_RSA_AES_128_SHA,
	SSL_RSA_CAMELLIA_128_SHA,
	SSL_RSA_DES_168_SHA,
	SSL_RSA_RC4_128_SHA,
//	SSL_RSA_RC4_128_MD5,
	0
};

static char *dhm_P = 
	"E4004C1F94182000103D883A448B3F80" \
	"2CE4B44A83301270002C20D0321CFD00" \
	"11CCEF784C26A400F43DFB901BCA7538" \
	"F2C6B176001CF5A0FD16D2C48B1D0C1C" \
	"F6AC8E1DA6BCC3B4E1F96B0564965300" \
	"FFA1D0B601EB2800F489AA512C4B248C" \
	"01F76949A60BB7F00A40B1EAB64BDD48" \
	"E8A700D60B7F1200FA8E77B0A979DABF";
static char *dhm_G = "4";

static char *ssl_error_logfile;
static rsa_context rsa;
static pthread_mutex_t random_mutex;
static ctr_drbg_context ctr_drbg;
static entropy_context entropy;

/* Initialize SSL library
 */
void ssl_initialize(char *logfile) {
	ssl_error_logfile = logfile;

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	entropy_init(&entropy);
	ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char*)"Hiawatha_RND", 10);
	ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);
	pthread_mutex_init(&random_mutex, NULL);
}

/* SSL debug callback function
 */
static void ssl_debug(void UNUSED(*ctx), int level, const char *str) {
	if (level >= ENABLE_DEBUG_LEVEL) {
		return;
	}

	log_string(ssl_error_logfile, "PolarSSL error|%s", str);
}

/* Required to use random number generator functions in a multithreaded application
 */
static int ssl_random(void *p_rng, unsigned char *output, size_t len) {
	int result;

	pthread_mutex_lock(&random_mutex);
	result = ctr_drbg_random(p_rng, output, len);
	pthread_mutex_unlock(&random_mutex);

	return result;
}

/* Load private key and certificate from file
 */
int ssl_load_key_cert(char *file, rsa_context **private_key, x509_cert **certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*private_key = (rsa_context*)malloc(sizeof(rsa_context))) == NULL) {
		return -1;
	}
	memset(*private_key, 0, sizeof(rsa_context));

	if ((result = x509parse_keyfile(*private_key, file, NULL)) != 0) {
		fprintf(stderr, "Error loading RSA private key (%X).\n", result);
		return -1;
	}

	if ((*certificate = (x509_cert*)malloc(sizeof(x509_cert))) == NULL) {
		return -1;
	}
	memset(*certificate, 0, sizeof(x509_cert));

	if ((result = x509parse_crtfile(*certificate, file)) != 0) {
		fprintf(stderr, "Error loading X509 certificates (%X).\n", result);
		return -1;
	}

	return 0;
}

/* Load CA certificate from file.
 */
int ssl_load_ca_cert(char *file, x509_cert **ca_certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_certificate = (x509_cert*)malloc(sizeof(x509_cert))) == NULL) {
		return -1;
	}
	memset(*ca_certificate, 0, sizeof(x509_cert));

	if ((result = x509parse_crtfile(*ca_certificate, file)) != 0) {
		fprintf(stderr, "Error loading X509 CA certificate (%X).\n", result);
		return -1;
	}

	return 0;
}

/* Load CA CRL from file
 */
int ssl_load_ca_crl(char *file, x509_crl **ca_crl) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_crl = (x509_crl*)malloc(sizeof(x509_crl))) == NULL) {
		return -1;
	}
	memset(*ca_crl, 0, sizeof(x509_crl));

	if ((result = x509parse_crlfile(*ca_crl, file)) != 0) {
		fprintf(stderr, "Error loading X509 CA CRL (%X).\n", result);
		return -1;
	}

	return 0;
}

/* Accept incoming SSL connection
 */
int ssl_accept(t_ssl_accept_data *sad, int timeout) {
	int result, handshake;
	struct timeval timer;
	time_t start_time;

	if (ssl_init(sad->ssl) != 0) {
		return -1;
	}

	ssl_set_endpoint(sad->ssl, SSL_IS_SERVER);
	if (sad->ca_certificate == NULL) {
		ssl_set_authmode(sad->ssl, SSL_VERIFY_NONE);
	} else {
		ssl_set_authmode(sad->ssl, SSL_VERIFY_REQUIRED);
		ssl_set_ca_chain(sad->ssl, sad->ca_certificate, sad->ca_crl, NULL);
	}

	ssl_set_rng(sad->ssl, ssl_random, &ctr_drbg);
	ssl_set_dbg(sad->ssl, ssl_debug, stderr);
	ssl_set_bio(sad->ssl, net_recv, sad->client_fd, net_send, sad->client_fd);

	ssl_set_ciphersuites(sad->ssl, ciphersuites);

	memset(sad->session, 0, sizeof(ssl_session));
	ssl_set_session(sad->ssl, 0, 0, sad->session);

	ssl_set_own_cert(sad->ssl, sad->certificate, sad->private_key);
	ssl_set_dh_param(sad->ssl, dhm_P, dhm_G);

	timer.tv_sec = timeout;
	timer.tv_usec = 0;
	setsockopt(*(sad->client_fd), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	start_time = time(NULL);

	result = 0;
	while ((handshake = ssl_handshake(sad->ssl)) != 0) {
		if ((handshake != POLARSSL_ERR_NET_WANT_READ) && (handshake != POLARSSL_ERR_NET_WANT_WRITE)) {
			ssl_free(sad->ssl);
			sad->ssl = NULL;
			result = -1;
			break;
		}
		if (time(NULL) - start_time >= timeout) {
			ssl_free(sad->ssl);
			sad->ssl = NULL;
			result = -2;
			break;
		}
	}

	timer.tv_sec = 0;
	timer.tv_usec = 0;
	setsockopt(*(sad->client_fd), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));

	return result;
}

/* See if data from SSL connection is read to be read
 */
int ssl_pending(ssl_context *ssl) {
	return ssl_get_bytes_avail(ssl);
}

/* Read data from SSL connection
 */
int ssl_receive(ssl_context *ssl, char *buffer, unsigned int maxlength) {
	int result;

	do {
		result = ssl_read(ssl, (unsigned char*)buffer, maxlength);
	} while (result == POLARSSL_ERR_NET_WANT_READ);

	if (result < 0) {
		return -1;
	}

	return result;
}

/* Send data via SSL connection
 */
int ssl_send(ssl_context *ssl, const char *buffer, unsigned int length) {
	int result;

	do {
		result = ssl_write(ssl, (unsigned char*)buffer, length);
	} while (result == POLARSSL_ERR_NET_WANT_WRITE);

	if (result < 0) {
		return -1;
	}

	return result;
}

/* Get information from client certificate
 */
int get_client_crt_info(ssl_context *ssl, char *subject, char *issuer, int length) {
	if (ssl->peer_cert == NULL) {
		return -1;
	}

	if (x509parse_dn_gets(subject, length, &(ssl->peer_cert->subject)) == -1) {
		return -1;
	}
	subject[length - 1] = '\0';

	if (x509parse_dn_gets(issuer, length, &(ssl->peer_cert->issuer)) == -1) {
		return -1;
	}
	issuer[length - 1] = '\0';

	return 0;
}

/* Close SSL connection
 */
void ssl_close(ssl_context *ssl) {
	if (ssl != NULL) {
		ssl_close_notify(ssl);
		ssl_free(ssl);
	}
}

/* Clean up SSL library
 */
void ssl_shutdown(void) {
	rsa_free(&rsa);
}

#ifdef ENABLE_RPROXY
int ssl_connect(ssl_context *ssl, ssl_session *ssn, int *sock) {
	memset(ssn, 0, sizeof(ssl_session));
	memset(ssl, 0, sizeof(ssl_context));

	if (ssl_init(ssl) != 0) {
		return -1;
	}

	ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	ssl_set_authmode(ssl, SSL_VERIFY_NONE);

	ssl_set_rng(ssl, ssl_random, &ctr_drbg);
	ssl_set_dbg(ssl, ssl_debug, stderr);
	ssl_set_bio(ssl, net_recv, sock, net_send, sock);

	ssl_set_ciphersuites(ssl, ciphersuites);
	ssl_set_session(ssl, 0, 0, ssn);

	if (ssl_handshake(ssl) != 0) {
		return -1;
	}

	return 0;
}

int ssl_send_completely(ssl_context *ssl, const char *buffer, int size) {
	int bytes_written, total_written = 0;

	while (total_written < size) {
		if ((bytes_written = ssl_write(ssl, (unsigned char*)buffer + total_written, size - total_written)) == -1) {
			return -1;
		} else {
			total_written += bytes_written;
		}
	}

	return total_written;
}
#endif

#endif
