#ifndef ERROR_H
#define ERROR_H

#define CERROR(code, format, ...) \
    do { snprintf(errmsg, ERR_MESSAGE_LEN, format, ##__VA_ARGS__); \
        errmsg[ERR_MESSAGE_LEN - 1] = 0; \
        rv = code; \
        goto err; } while(0)

#endif
