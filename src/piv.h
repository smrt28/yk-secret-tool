#ifndef YUBICO_PIV_H
#define YUBICO_PIV_H

#define ERR_YK_INIT        -100
#define ERR_YK_WRONG_PIN   -101
#define ERR_YK_VERIFY      -102
#define ERR_YK_NOTSET      -103
#define ERR_YK_ARGS        -104
#define ERR_YK_INVALID     -105
#define ERR_YK_GENERAL     -106
#define ERR_YK_CRYPTO      -107
#define ERR_YK_ALLOC       -108
#define ERR_YK_INPUT       -109

#define YKPIV_PIN_MAX_SIZE 8
#define YKPIV_PIN_MIN_SIZE 6
#define YKPIV_PIN_BUF_SIZE (YKPIV_PIN_MAX_SIZE + 1)

#define YKPIV_SECRET_LEN 32
#define YKPIV_ENCRYPTED_SECRET_LEN 256


#define YKPIV_SLOTS 21
#define YKPIV_SLOTS_RANGE "[1-21]"

#define ERR_MESSAGE_LEN	1024

#include <stdint.h>

struct ykpiv_state;

int ykpiv_fetch_secret(int n, const char *pin, unsigned char *secret_out,
        char *errmsg);

int ykpiv_init_and_verify(struct ykpiv_state **state,
        const char *pin, const char *mgm_key, char *errmsg);


int ykpiv_select_slot(size_t n, uint8_t *key, int *object_id);

int ykpiv_getpin(char *pin);

#endif
