/*
 *
 *  Created on: May 1, 2013
 *      Author: yogesh
 */
#include <avr.h>


RESULT do_test(WORD b)
{
    WORD x = 0;
    SHORT a = 0;
    x = b*b & 0xFFFF;
    a = (SHORT) x;
    return a;
}

int main( void )
{
    uart_init();
    int i = 0;
    while( 1 )
    {
        if( i == 28 )
        {
            do_test(i);
        } else
        {
            printf( "Tick tock [%d]\r\n", i );
        }
        i++;
        if( i > 254 ) i = 0;
    }
}
