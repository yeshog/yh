#include <common.h>

#define FOSC 16000000
#define BAUD 9600
#define MYUBRR FOSC/16/BAUD-1

uint8_t uart_getchar( void );
int uart_putchar(char c, FILE *stream);
void uart_init(void);
