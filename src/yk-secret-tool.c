
#include <unistd.h>
#include <getopt.h>
#include <ykpiv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <openssl/rsa.h>
#include <openssl/rand.h>

#include "piv.h"
#include "error.h"
#include "safe-mem.h"


struct _ykey_options {
    const char *mgm;
    int slot;
    const char *action;
    const char *pin;
    const char *secret;
};

static void print_hex(unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}

static int _generate_key(int n, struct ykpiv_state *state,
        const unsigned char *secret, char *errmsg) {
    uint8_t slot = 0;
    int object_id = 0;

    unsigned char *data = NULL;
    unsigned char *secretbuf = NULL;
    uint8_t *mod = NULL, *exp = NULL;
    size_t mod_len = 0, exp_len = 0;
    int rv = 0;
    RSA *rsa = NULL;
    BIGNUM *bignum_n = NULL, *bignum_e = NULL;

    if (ykpiv_select_slot(n, &slot, &object_id))
        CERROR(ERR_YK_ARGS, "Invalid slot number "
                YKPIV_SLOTS_RANGE);

    if (ykpiv_util_generate_key(state,
            slot, YKPIV_ALGO_RSA2048,
            YKPIV_PINPOLICY_DEFAULT,
            YKPIV_TOUCHPOLICY_DEFAULT,
            &mod, &mod_len, &exp,
            &exp_len, NULL, NULL) != YKPIV_OK)
        CERROR(ERR_YK_GENERAL, "Yubico failed to generate RSA key; "
                "slot=%x", slot);

    bignum_n = BN_bin2bn(mod, mod_len, NULL);
    if (!bignum_n) CERROR(ERR_YK_CRYPTO, "Lib crypto failed");

    bignum_e = BN_bin2bn(exp, exp_len, NULL);
    if (!bignum_e) CERROR(ERR_YK_CRYPTO, "Lib crypto failed");

    rsa = RSA_new();
    if (!rsa) CERROR(ERR_YK_CRYPTO, "Lib crypto failed");

    if (RSA_set0_key(rsa, bignum_n, bignum_e, NULL) != 1)
        CERROR(ERR_YK_CRYPTO, "Lib crypto failed");

    bignum_n = bignum_e = NULL;

    data = alloc_safe_mem(YKPIV_ENCRYPTED_SECRET_LEN);
    if (!data) CERROR(ERR_YK_ALLOC, "Error allocating memory for encrypted secret");

    if (!secret) {
        secretbuf = alloc_safe_mem(YKPIV_SECRET_LEN);
        if (!secretbuf) CERROR(ERR_YK_ALLOC, "Error allocating memory for secret buffer");

        secret = secretbuf;
        RAND_bytes(secretbuf, YKPIV_SECRET_LEN);
    }

    int len = RSA_public_encrypt(YKPIV_SECRET_LEN,
            secret, data, rsa, RSA_PKCS1_PADDING);

    if (len != YKPIV_ENCRYPTED_SECRET_LEN) CERROR(ERR_YK_CRYPTO, "RSA encrypt failed");

    if (ykpiv_save_object(state, object_id, data, YKPIV_ENCRYPTED_SECRET_LEN) != YKPIV_OK)
        CERROR(ERR_YK_INVALID, "Yubikey faled to write data object");
err:
    if (rsa) RSA_free(rsa);
    if (bignum_n) OPENSSL_free(bignum_n);
    if (bignum_e) OPENSSL_free(bignum_e);

    free_safe_mem(secretbuf);
    free_safe_mem(data);
    return rv;
}

static int generate_key(int n, const char *mgm, const char *hexsecret) {
    char errmsg[ERR_MESSAGE_LEN];
    int rv = 0;
    struct ykpiv_state *state = NULL;

    if (!mgm) mgm = "010203040506070801020304050607080102030405060708";

    rv = ykpiv_init_and_verify(&state, NULL, mgm, errmsg);
    if (rv != 0) goto err;

    if (hexsecret) {
        unsigned char secret[YKPIV_SECRET_LEN];
        size_t len = sizeof(secret);

        if (ykpiv_hex_decode(hexsecret, strlen(hexsecret), secret, &len)
                != YKPIV_OK || len != sizeof(secret))
        {
            CERROR(ERR_YK_ARGS,
                    "invalid secret length (must be 64 hexa chars)");

        }

        rv = _generate_key(n, state, secret, errmsg);
    } else {
        rv = _generate_key(n, state, NULL, errmsg);
    }


    if (rv != 0) goto err;

    ykpiv_done(state);
    return 0;
err:
    if (state) ykpiv_done(state);
    printf("err: message: %s code:%d\n", errmsg, rv);
    return -1;
}


static void usage() {
    printf("usage: yk-secret-tool -a action (setup|fetch) "
                "-s slot [-p pin] [-k mgm_key] [-x secret]\n\n"
            "-a, --action\t setup|fetch\n"
            "-s, --slot\t Yubico slot order [1-20]\n"
            "-k, --mgm-key\t PIV mgm key\n"
            "-p, --pin\t PIV pin\n"
            "-x, --secret\t 64 hex characters secret\n");
}


int main(int argc, char **argv) {
    int option_index = 0;
    int c, rv = 0, len;

    char *pinbuf = NULL;
    char errmsg[ERR_MESSAGE_LEN];
    struct _ykey_options o;

    if (argc == 1) {
        usage();
        return 1;
    }

    pinbuf = alloc_safe_mem(YKPIV_PIN_BUF_SIZE);

    if (!pinbuf) {
        CERROR(ERR_YK_GENERAL, "can't allocate memory");
    }

    memset(&o, 0, sizeof(o));
    memset(pinbuf, 0, YKPIV_PIN_BUF_SIZE);


    for (;;) {
        static struct option long_options[] = {
            { "mgm-key", optional_argument, 0, 'k' },
            { "slot", required_argument, 0, 's' },
            { "action", required_argument, 0, 'a' },
            { "pin", optional_argument, 0, 'p' },
            { "secret", optional_argument, 0, 'x' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "a:k:s:hp:x:", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 'a':
                o.action = optarg;
                break;
            case 'k':
                o.mgm = optarg;
                break;
            case 's':
                o.slot = atoi(optarg);
                break;
            case 'p':
                o.pin = optarg;
                break;
            case 'x':
                o.secret = optarg;
                break;
            case 'h':
                usage();
                return 1;
            default:
                CERROR(ERR_YK_ARGS, "Unknown option\n");
        }
    }

    if (o.slot < 1 || o.slot > YKPIV_SLOTS) {
        CERROR(ERR_YK_ARGS,
                "slot must be a number in range "
                YKPIV_SLOTS_RANGE);
    }

    if (!o.action) {
        CERROR(ERR_YK_ARGS, "yk-secret-tool: -a option required");
    }

    if (o.secret && strlen(o.secret) != 64) {
        CERROR(ERR_YK_ARGS, "invalid secret length (must be 64 hexa chars");
    }

    if (strcmp(o.action, "setup") == 0) {
        printf("Generating key and setting secret to slot %d...\n", o.slot);
        generate_key(o.slot, o.mgm, o.secret);
        printf("Done\n");
    } else if (strcmp(o.action, "fetch") == 0) {
        unsigned char secret[YKPIV_SECRET_LEN];

        memset(secret, 0, sizeof(secret));
        len = 0;
        if (!o.pin) {
            if (ykpiv_getpin(pinbuf) != 0) {
                CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
            }
            o.pin = pinbuf;
        } else {
            len = strlen(o.pin);
            if (len < YKPIV_PIN_MIN_SIZE || len > YKPIV_PIN_MAX_SIZE) {
                CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
            }
        }

        if ((rv = ykpiv_fetch_secret(o.slot, o.pin, secret, errmsg)) == 0) {
            print_hex(secret, sizeof(secret));
        } else {
            goto err;
        }

    } else {
        CERROR(ERR_YK_ARGS, "unknwon action");
    }

    rv = 0;
err:
    if (rv) {
        fprintf(stderr, "error: %s; [error-code=%d]\n", errmsg, rv);
    }

    free_safe_mem(pinbuf);
    return rv;
}
