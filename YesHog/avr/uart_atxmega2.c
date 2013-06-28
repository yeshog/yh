#include "avr.h"

static FILE mystdout = FDEV_SETUP_STREAM (uart_putchar, NULL, _FDEV_SETUP_WRITE);

int uart_putchar (char c, FILE *stream)
{
    if (c == '\n')
        uart_putchar('\r', stream);

    // Wait for the transmit buffer to be empty
    while ( !( USARTC0.STATUS & USART_DREIF_bm ) );

    // Put our character into the transmit buffer
    USARTC0.DATA = c;

    return 0;
}


// Init USART.  Transmit only (we're not receiving anything)
// We use USARTC0, transmit pin on PC3.
// Want 9600 baud. Have a 2 MHz clock. BSCALE = 0
// BSEL = ( 2000000 / (2^0 * 16*9600)) -1 = 12
// Fbaud = 2000000 / (2^0 * 16 * (12+1))  = 9615 bits/sec
void uart_init (void)
{

    PORTD_DIRSET = (1 << 3); /* PD3 is PICO_UART TX  */
    PORTD_DIRCLR = (1 << 2); /* PD2 is PICO_UART RX  */

    // Set baud rate & frame format
    USARTD0.BAUDCTRLB = 0;			// BSCALE = 0 as well
    USARTD0.BAUDCTRLA = 12;

    // Set mode of operation
    USARTD0.CTRLA = 0;				// no interrupts please
    USARTD0.CTRLC = 0x03;			// async, no parity, 8 bit data, 1 stop bit

    // Enable transmitter only
    USARTD0.CTRLB = USART_TXEN_bm;
    stdout = &mystdout;
}
