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

#define ENABLE_DEBUG_LEVEL      0
#define TIMESTAMP_SIZE         40
#define SNI_MAX_HOSTNAME_LEN  128

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
#include "libstr.h"
#include "log.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"
#include "polarssl/dhm.h"
#include "polarssl/ssl_cache.h"

typedef struct type_sni_list {
	t_charlist *hostname;
	rsa_context *private_key;
	x509_cert *certificate;
	x509_cert *ca_certificate;
	x509_crl  *ca_crl;

	struct type_sni_list *next;
} t_sni_list;

static int ciphersuites[] = {
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	0
};

static char *ssl_error_logfile;
static rsa_context rsa;
static pthread_mutex_t random_mutex;
static pthread_mutex_t cache_mutex;
static ctr_drbg_context ctr_drbg;
static entropy_context entropy;
static t_sni_list *sni_list = NULL;
static ssl_cache_context cache;

/* Initialize SSL library
 */
void ssl_initialize(char *logfile) {
	ssl_error_logfile = logfile;

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	entropy_init(&entropy);
	ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char*)"Hiawatha_RND", 10);
	ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);

	ssl_cache_init(&cache);
	ssl_cache_set_max_entries(&cache, 100);

	pthread_mutex_init(&random_mutex, NULL);
	pthread_mutex_init(&cache_mutex, NULL);
}

/* Add SNI information to list
 */
int ssl_register_sni(t_charlist *hostname, rsa_context *private_key, x509_cert *certificate,
                x509_cert *ca_certificate, x509_crl *ca_crl) {
	t_sni_list *sni;

	if ((sni = (t_sni_list*)malloc(sizeof(t_sni_list))) == NULL) {
		return -1;
	}

	sni->hostname = hostname;
	sni->private_key = private_key;
	sni->certificate = certificate;
	sni->ca_certificate = ca_certificate;
	sni->ca_crl = ca_crl;

	sni->next = sni_list;
	sni_list = sni;

	return 0;
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

/* Required to use the SSL cache in a multithreaded application
 */
static int ssl_get_cache(void *data, ssl_session *session) {
	int result;

	pthread_mutex_lock(&cache_mutex);
	result = ssl_cache_get(data, session);
	pthread_mutex_unlock(&cache_mutex);

	return result;
}

static int ssl_set_cache(void *data, const ssl_session *session) {
	int result;

	pthread_mutex_lock(&cache_mutex);
	result = ssl_cache_set(data, session);
	pthread_mutex_unlock(&cache_mutex);

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

/* Server Name Indication callback function
 */
static int sni_callback(void UNUSED(*parameter), ssl_context *context, const unsigned char *sni_hostname, size_t len) {
	char hostname[SNI_MAX_HOSTNAME_LEN + 1];
	t_sni_list *sni;
	int i;

	if (len > SNI_MAX_HOSTNAME_LEN) {
		return -1;
	}
	memcpy(hostname, sni_hostname, len);
	hostname[len] = '\0';

	sni = sni_list;
	while (sni != NULL) {
		for (i = 0; i < sni->hostname->size; i++) {
			if (hostname_match(hostname, *(sni->hostname->item + i))) {
				/* Set private key and certificate
				 */
				if ((sni->private_key != NULL) && (sni->certificate != NULL)) {
					ssl_set_own_cert(context, sni->certificate, sni->private_key);
				}

				/* Set CA certificate for SSL client authentication
				 */
				if (sni->ca_certificate != NULL) {
					ssl_set_authmode(context, SSL_VERIFY_REQUIRED);
					ssl_set_ca_chain(context, sni->ca_certificate, sni->ca_crl, NULL);
				}

				return 0;
			}
		}
		sni = sni->next;
	}

	return 0;
}

/* Accept incoming SSL connection
 */
int ssl_accept(t_ssl_accept_data *sad, int timeout, int min_ssl_version) {
	int result, handshake, skip;
	struct timeval timer;
	time_t start_time;

	if (ssl_init(sad->context) != 0) {
		return -1;
	}

	ssl_set_endpoint(sad->context, SSL_IS_SERVER);
	if (sad->ca_certificate == NULL) {
		ssl_set_authmode(sad->context, SSL_VERIFY_NONE);
	} else {
		ssl_set_authmode(sad->context, SSL_VERIFY_REQUIRED);
		ssl_set_ca_chain(sad->context, sad->ca_certificate, sad->ca_crl, NULL);
	}

	ssl_set_min_version(sad->context, SSL_MAJOR_VERSION_3, min_ssl_version);
	ssl_set_renegotiation(sad->context, SSL_RENEGOTIATION_DISABLED);

	ssl_set_rng(sad->context, ssl_random, &ctr_drbg);
	ssl_set_dbg(sad->context, ssl_debug, stderr);
	ssl_set_bio(sad->context, net_recv, sad->client_fd, net_send, sad->client_fd);
	ssl_set_sni(sad->context, sni_callback, NULL);

	ssl_set_session_cache(sad->context, ssl_get_cache, &cache, ssl_set_cache, &cache);

	if ((min_ssl_version >= SSL_MINOR_VERSION_2) && (ciphersuites[0] == TLS_RSA_WITH_RC4_128_SHA)) {
		skip = 1;
	} else {
		skip = 0;
	}
	ssl_set_ciphersuites(sad->context, ciphersuites + skip);

	ssl_set_own_cert(sad->context, sad->certificate, sad->private_key);
	ssl_set_dh_param(sad->context, POLARSSL_DHM_RFC5114_MODP_2048_P, POLARSSL_DHM_RFC5114_MODP_2048_G);

	timer.tv_sec = timeout;
	timer.tv_usec = 0;
	setsockopt(*(sad->client_fd), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	start_time = time(NULL);

	result = 0;
	while ((handshake = ssl_handshake(sad->context)) != 0) {
		if ((handshake != POLARSSL_ERR_NET_WANT_READ) && (handshake != POLARSSL_ERR_NET_WANT_WRITE)) {
			ssl_free(sad->context);
			sad->context = NULL;
			result = -1;
			break;
		}
		if (time(NULL) - start_time >= timeout) {
			ssl_free(sad->context);
			sad->context = NULL;
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
int get_client_crt_info(ssl_context *context, char *subject, char *issuer, int length) {
	if (context->session == NULL) {
		return -1;
	} else if (context->session->peer_cert == NULL) {
		return -1;
	}

	if (x509parse_dn_gets(subject, length, &(context->session->peer_cert->subject)) == -1) {
		return -1;
	}
	subject[length - 1] = '\0';

	if (x509parse_dn_gets(issuer, length, &(context->session->peer_cert->issuer)) == -1) {
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
	ssl_cache_free(&cache);
}

#ifdef ENABLE_RPROXY
int ssl_connect(ssl_context *ssl, int *sock, char *hostname) {
	memset(ssl, 0, sizeof(ssl_context));
	if (ssl_init(ssl) != 0) {
		return -1;
	}

	ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	ssl_set_authmode(ssl, SSL_VERIFY_NONE);

	ssl_set_rng(ssl, ssl_random, &ctr_drbg);
	ssl_set_dbg(ssl, ssl_debug, stderr);
	ssl_set_bio(ssl, net_recv, sock, net_send, sock);

	if (hostname != NULL) {
		ssl_set_hostname(ssl, hostname);
	}
	ssl_set_ciphersuites(ssl, ciphersuites);

	if (ssl_handshake(ssl) != 0) {
		return -1;
	}

	return 0;
}

int ssl_send_completely(ssl_context *ssl, const char *buffer, int size) {
	int bytes_written, total_written = 0;

	if (size <= 0) {
		return 0;
	} else while (total_written < size) {
		if ((bytes_written = ssl_write(ssl, (unsigned char*)buffer + total_written, size - total_written)) > 0) {
			total_written += bytes_written;
		} else if (bytes_written != POLARSSL_ERR_NET_WANT_WRITE) {
			return -1;
		}
	}

	return total_written;
}
#endif

#endif
