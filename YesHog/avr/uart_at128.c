#include "avr.h"

static FILE mystdout =
      FDEV_SETUP_STREAM(uart_putchar,
      NULL, _FDEV_SETUP_WRITE);

int uart_putchar(char c, FILE *stream)
{
    if (c == '\n')
        uart_putchar('\r', stream);

    /* wait for UDR to be clear */
    loop_until_bit_is_set(UCSR0A, UDRE0);
    UDR0 = c;
    /* send the character */
    return 0;

}

void uart_init()
{
    UBRR0H = (MYUBRR) >> 8;
    UBRR0L = MYUBRR;
    UCSR0B = (1<<RXEN0)|(1<<TXEN0);
    stdout = &mystdout;
}

uint8_t uart_getchar( void )
{
    /* Wait for data to be received */
    while ( !( UCSR0A & ( 1<<RXC0 ) ) );
    /* Get and return received data from buffer */
    return UDR0;
}
