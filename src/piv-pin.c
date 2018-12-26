#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "error.h"
#include "piv.h"

#include "safe-mem.h"

static struct termios termios_old;
static int tty_fd;

static void sigint_termios(int sa)
{
    tcsetattr(tty_fd, TCSAFLUSH, &termios_old);
    exit(sa);
}

static int read_passphrase(const char *prompt, char *pass, size_t bufsz)
{
    struct termios termios_new;
    ssize_t n;
    int fd = STDIN_FILENO, r = 0;
    struct sigaction act, old_act;
    int is_tty = isatty(fd);

    if (is_tty == 0)
        errno = 0;

    memset(pass, 0, bufsz);

    printf("%s", prompt);
    fflush(stdout);

    if (is_tty) {
        tcgetattr(fd, &termios_old);
        memcpy(&termios_new, &termios_old, sizeof(termios_new));
        termios_new.c_lflag &= ~ECHO;

        act.sa_handler = sigint_termios;
        act.sa_flags   = SA_RESETHAND;
        sigemptyset(&act.sa_mask);

        tty_fd = fd;
        sigaction(SIGINT, &act, &old_act);

        tcsetattr(fd, TCSAFLUSH, &termios_new);
    }

    n = read(fd, pass, bufsz);
    if (n > 0) {
        pass[n-1] = '\0'; /* Strip trailing \n */
    } else {
        r = -1;
    }

    if (is_tty) {
        tcsetattr(fd, TCSAFLUSH, &termios_old);
        putchar('\n');

        sigaction(SIGINT, &old_act, NULL);
    }

    return r;
}

int ykpiv_getpin(char *pin) {
    char *pas = NULL;
    pas = alloc_safe_mem(YKPIV_PIN_BUF_SIZE + 1);
    if (!pas) {
        pin[0] = 0;
        return -1;
    }

    memset(pas, 0, YKPIV_PIN_BUF_SIZE + 1);

    // read +1 character above maximum to detect too long pin
    read_passphrase("Yubikey PIN:", pas, YKPIV_PIN_BUF_SIZE + 1);

    int len = strlen(pas);
    if (len < YKPIV_PIN_MIN_SIZE || len > YKPIV_PIN_MAX_SIZE) {
        pin[0] = 0;
        free_safe_mem(pas);
        return -1;
    }

    memcpy(pin, pas, len);
    free_safe_mem(pas);
    return 0;
}
