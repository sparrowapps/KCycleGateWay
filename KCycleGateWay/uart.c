#include "main.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <termios.h>
#include "micomd.h"
#include <stdint.h>
#include <stdarg.h>
#include <sys/ioctl.h>

static struct termios options;
#if 1
static struct termios option_tmp;
#endif

static int initport(int fd)
{
    struct termios newoptions;

    tcgetattr (fd, &options);

    printf("Default Setting of Baudrate is %x   =========================\n", options.c_cflag);

    bzero (&newoptions, sizeof (newoptions));

    newoptions.c_cflag  = (CLOCAL | CREAD | CS8 | B19200);
    newoptions.c_iflag      = IGNPAR;
    newoptions.c_oflag      = 0;
    newoptions.c_lflag      = 0;
    newoptions.c_cc[VMIN]   = 1;
    newoptions.c_cc[VTIME]  = 0;

    tcflush (fd, TCIFLUSH);

    tcsetattr (fd, TCSANOW, &newoptions);
    printf("New Setting of Baudrate is %x   =========================\n", newoptions.c_cflag);

    tcgetattr (fd, &option_tmp);

    return 1;
}

int uart_open (void)
{
    int uart_fd;

    uart_fd = open("/dev/serial0", O_RDWR | O_NOCTTY | O_NDELAY);
    if(uart_fd > 0)
    {
        printf("Opened device ttyS0  fd = %d    \n", uart_fd);
    }
    else
    {
        uart_fd = open("/dev/serial1", O_RDWR | O_NOCTTY | O_NDELAY);
        if(uart_fd > 0)
        {
            printf("Opened device ttyAMA0  fd = %d  ..................\n", uart_fd);
        }
    }

    fcntl (uart_fd, F_SETFL, 0);
    initport (uart_fd);

    return uart_fd;
}

int uart_close (int uart_fd)
{
    tcsetattr(uart_fd, TCSANOW, &options);
    ioctl(uart_fd, TCSANOW, (void *)&options);
    close (uart_fd);

    return 0;
}

