/*
* TLS sessions tickets key_name dump utility.
*
* Copyright (C) 2016 by Andrey Domas <andrey.domas@gmail.com>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define DEFAULT_PORT "443"

#define BOOL_OPT_VERBOSE 1
#define BOOL_OPT_RAW 2
#define BOOL_OPT_HEXDUMP 4

#define KEY_NAME_LENGTH 16

BIO *bio_stderr;
int bool_options = 0;
int exit_code = 0;
char *host;

int error(char *msg) {
    if (bool_options & BOOL_OPT_VERBOSE)
        ERR_print_errors(bio_stderr);
    BIO_printf(bio_stderr, "%s\n", msg);
    abort();
}

void print_key_name(char key_name[KEY_NAME_LENGTH]) {
    BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO *bio_base64;

    if (bio_stdout == NULL)
        error("Unable to get stdout BIO");

    if (bool_options & BOOL_OPT_HEXDUMP)
        BIO_dump_indent(bio_stdout, key_name, KEY_NAME_LENGTH, 0);

    else if (bool_options & BOOL_OPT_RAW)
        BIO_write(bio_stdout, key_name, KEY_NAME_LENGTH);

    else {
        bio_base64 = BIO_new(BIO_f_base64());
        BIO_push(bio_base64, bio_stdout);
        BIO_write(bio_base64, key_name, KEY_NAME_LENGTH);
        BIO_flush(bio_base64);
    }

    BIO_free_all(bio_stdout);
}

void get_key_name() {
    SSL_CTX* ctx = NULL;
    BIO *conn = NULL;
    SSL *ssl = NULL;
    SSL_SESSION *session = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    const SSL_METHOD* method = TLSv1_2_client_method();
    if(method == NULL)
        error("Unable to create SSL-method");

    ctx = SSL_CTX_new(method);
    if(ctx == NULL)
        error("Unable to create SSL-context");

    conn = BIO_new_ssl_connect(ctx);
    if(conn == NULL)
        error("Unable to create connection BIO");

    BIO_set_conn_hostname(conn, host);

    BIO_get_ssl(conn, &ssl);
    if(ssl == NULL)
        error("Unable to get SSL-pointer from SSL-context");

    if(BIO_do_connect(conn) <= 0)
        error("Unable to connect to remote host");

    //if(BIO_do_handshake(conn) <= 0) error();

    session = SSL_get_session(ssl);
    if (session == NULL)
        error("Unable to get session");

    if (session->tlsext_ticklen > 16) {
        print_key_name((char *)session->tlsext_tick);
    }

    if(conn != NULL)
      BIO_free_all(conn);

    if(NULL != ctx)
      SSL_CTX_free(ctx);
}


static void usage() {
    BIO_printf(bio_stderr,"Usage: get_tls_ticket_key_name [options] host[:port]\n");
    BIO_printf(bio_stderr,"\n");
    BIO_printf(bio_stderr,"Options:\n");
    BIO_printf(bio_stderr," -v          - verbose output\n");
    BIO_printf(bio_stderr," -r          - print key_name as is (binary output instead of base64)\n");
    BIO_printf(bio_stderr," -x          - print key_name hex dump (instead of base64) \n");
    BIO_printf(bio_stderr," -h, --help  - print this message and exit\n");
}


int main(int argc, char **argv) {
    bio_stderr = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (bio_stderr == NULL)
        error("Unable to get stderr BIO");

#ifdef OPENSSL_NO_TLSEXT
    BIO_printf(bio_stderr, "OpenSSL must be built with TLSEXT support\n");
    exit_code = 2;
    goto exit;
#endif

    argc--;
    argv++;

    while (argc >= 1) {
        if (strcmp(*argv,"-v") == 0) {
            bool_options |= BOOL_OPT_VERBOSE;
            SSL_load_error_strings();
        }
        else if (strcmp(*argv,"-r") == 0) {
            bool_options |= BOOL_OPT_RAW;
        }
        else if (strcmp(*argv,"-x") == 0) {
            bool_options |= BOOL_OPT_HEXDUMP;
        }

        else if (strcmp(*argv,"-h") == 0) {
            usage();
            goto exit;
        }
        else if (strcmp(*argv,"--help") == 0) {
            usage();
            goto exit;
        }
        else if (--argc < 1) {
            host = *argv;
            if (strchr(host, ':') == NULL)
                strcat(host, ":" DEFAULT_PORT);
        }
        else {
            BIO_printf(bio_stderr, "Unknown option %s\n", *argv);
            usage();
            exit_code = 1;
            goto exit;
        }

        argc--;
        argv++;
    }

    get_key_name();

exit:
    BIO_free_all(bio_stderr);
    exit(exit_code);
}

