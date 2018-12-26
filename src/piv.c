#include <string.h>

#include <ykpiv.h>
#include <openssl/pkcs12.h>

#include "piv.h"
#include "error.h"

#include "safe-mem.h"

#ifdef TC_YK_DEBUG
#define YK_DEBUG 1
#else
#define YK_DEBUG 0
#endif

#define KEY_LEN 24
#define YKPIV_ENCRYPTED_SECRET_LEN 256


int ykpiv_select_slot(size_t n, uint8_t *key, int *object_id) {
    static uint8_t retired_keys[] = {
        YKPIV_KEY_RETIRED1, YKPIV_KEY_RETIRED2, YKPIV_KEY_RETIRED3,
        YKPIV_KEY_RETIRED4, YKPIV_KEY_RETIRED5, YKPIV_KEY_RETIRED6,
        YKPIV_KEY_RETIRED7, YKPIV_KEY_RETIRED8, YKPIV_KEY_RETIRED9,
        YKPIV_KEY_RETIRED10, YKPIV_KEY_RETIRED11, YKPIV_KEY_RETIRED12,
        YKPIV_KEY_RETIRED13, YKPIV_KEY_RETIRED14, YKPIV_KEY_RETIRED15,
        YKPIV_KEY_RETIRED16, YKPIV_KEY_RETIRED17, YKPIV_KEY_RETIRED18,
        YKPIV_KEY_RETIRED19, YKPIV_KEY_RETIRED20,
        YKPIV_KEY_AUTHENTICATION // 21
    };

    static int retired_objects[] = {
        YKPIV_OBJ_RETIRED1, YKPIV_OBJ_RETIRED2, YKPIV_OBJ_RETIRED3,
        YKPIV_OBJ_RETIRED4, YKPIV_OBJ_RETIRED5, YKPIV_OBJ_RETIRED6,
        YKPIV_OBJ_RETIRED7, YKPIV_OBJ_RETIRED8, YKPIV_OBJ_RETIRED9,
        YKPIV_OBJ_RETIRED10, YKPIV_OBJ_RETIRED11, YKPIV_OBJ_RETIRED12,
        YKPIV_OBJ_RETIRED13, YKPIV_OBJ_RETIRED14, YKPIV_OBJ_RETIRED15,
        YKPIV_OBJ_RETIRED16, YKPIV_OBJ_RETIRED17, YKPIV_OBJ_RETIRED18,
        YKPIV_OBJ_RETIRED19, YKPIV_OBJ_RETIRED20,
        YKPIV_OBJ_AUTHENTICATION // 21
    };

    if (n > YKPIV_SLOTS || n < 1) return -1;
    *key = retired_keys[n-1];
    *object_id = retired_objects[n-1];
    return 0;
}

int ykpiv_init_and_verify(struct ykpiv_state **state,
        const char *pin, const char *mgm_key, char *errmsg)
{
    int rv = 0, tries = 0;

    *state = NULL;

    if (ykpiv_init(state, YK_DEBUG) != YKPIV_OK)
        CERROR(ERR_YK_INIT, "Yubikey init failed");

    if (ykpiv_connect(*state, NULL) != YKPIV_OK)
        CERROR(ERR_YK_INIT, "Yubikey connection failed");

    if (pin) {
        switch (ykpiv_verify(*state, pin, &tries)) {
            case YKPIV_OK: break;
            case YKPIV_WRONG_PIN:
                CERROR(ERR_YK_WRONG_PIN,
                        "Wrong Yubikey pin! (%d tries remaining)", tries);
                break;
            default:
                CERROR(ERR_YK_VERIFY, "Yubikey verification failed");
                break;
        }
    }

    if (mgm_key) {
        if (mgm_key[0] == 0) {
            if (ykpiv_authenticate(*state, NULL) != YKPIV_OK)
                CERROR(ERR_YK_VERIFY, "Yubikey MGM key check failed.");
        } else {
            unsigned char key[KEY_LEN];
            size_t key_len = sizeof(key);
            if (ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len) != YKPIV_OK)
                CERROR(ERR_YK_VERIFY, "Yubikey invalid MGM key");

            if (ykpiv_authenticate(*state, key) != YKPIV_OK)
                CERROR(ERR_YK_VERIFY, "Yubikey authenticate failed");
        }
    }

    return 0;

err:
    if (*state) {
        ykpiv_done(*state);
        *state = 0;
    }
    return rv;
}

static int _fetch_secret(struct ykpiv_state *state, int n,
        unsigned char *secret_out, char *errmsg)
{
    uint8_t slot = -1;
    int object_id = -1;

    int rv = 0;

    unsigned char data[YKPIV_ENCRYPTED_SECRET_LEN + 4]; // +4 bytes CRC
    size_t len = YKPIV_ENCRYPTED_SECRET_LEN + 4;
    unsigned char *data2 = NULL;
    unsigned char *secret = NULL;

    data2 = alloc_safe_mem(YKPIV_ENCRYPTED_SECRET_LEN + 4);
    if (!data2) CERROR(ERR_YK_ALLOC, "Error allocating memory for secret");

    secret = alloc_safe_mem(YKPIV_SECRET_LEN);
    if (!secret) CERROR(ERR_YK_ALLOC, "Error allocating memory for secret");

    if (ykpiv_select_slot(n, &slot, &object_id))
        CERROR(ERR_YK_ARGS, "Invalid slot number " YKPIV_SLOTS_RANGE);

    if (ykpiv_fetch_object(state, object_id, data, &len) != YKPIV_OK)
        CERROR(ERR_YK_NOTSET, "Can't fetch secret from Yubikey object 0x%x", object_id);

    if (len != YKPIV_ENCRYPTED_SECRET_LEN) CERROR(ERR_YK_INPUT,
            "Wrong expected Yubikey object length");

    if (ykpiv_decipher_data(state, data, YKPIV_ENCRYPTED_SECRET_LEN,
            data2, &len, YKPIV_ALGO_RSA2048, slot) != YKPIV_OK)
                CERROR(ERR_YK_CRYPTO, "Yubikey can't decrypt data");

    if (len != YKPIV_ENCRYPTED_SECRET_LEN) CERROR(ERR_YK_CRYPTO,
            "Wrong expected Yubikey object length");

    len = RSA_padding_check_PKCS1_type_2(secret, YKPIV_SECRET_LEN,
            data2 + 1, len - 1, YKPIV_ENCRYPTED_SECRET_LEN);

    if (len < 0) CERROR(ERR_YK_CRYPTO, "Lib crypto failed");

    memcpy(secret_out, secret, YKPIV_SECRET_LEN);

err:
    free_safe_mem(data2);
    free_safe_mem(secret);
    return rv;
}

int ykpiv_fetch_secret(int n, const char *pin,
        unsigned char *secret_out, char *errmsg)
{
    struct ykpiv_state *state = NULL;
    int rv = 0;

    rv = ykpiv_init_and_verify(&state, pin, NULL, errmsg);
    if (rv) goto err;

    rv = _fetch_secret(state, n, secret_out, errmsg);

err:
    if (state) ykpiv_done(state);
    return rv;
}
