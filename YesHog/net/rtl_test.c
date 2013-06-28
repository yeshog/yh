#include "rtl_drv.h"
#include <avr.h>
#include "l23.h"

extern BYTE __MAC[ 6 ];
extern BYTE __IP [ 4 ];
extern BYTE __PEER_IP[ 4 ];
extern BYTE __PEER_MAC[ 6 ];
extern SHORT __MYPORT;
extern yh_socket* conn;

int main(void)
{
    DECLARE( RESULT, _res_,   OK );
    DECLARE( SHORT,  rxlen,  OK  );
    DECLARE( BYTE*,  pkt,  NULL  );
    DECLARE( BYTE, byte_read, 0  );

    uart_init();
    init_RTL8019AS();
    show_regs();
    printf("YesHog\r\n");
    while(1)
    {
        rxlen = 0;
        _res_ = OK;
        pkt = NULL;
        check_for_incoming_pkt;
        if( _res_ != OK )
        {
            continue;
        }
        _res_ = get_frame( &pkt, &rxlen );
        if( _res_ != OK )
        {
            continue;
        }
        /* process_rx MUST free the packet */
        _res_ = process_rx( &pkt, rxlen );
        if( _res_ != OK )
        {
            printf( "Process RX result [%X]\r\n", _res_ );
        }
        printf( "Processing result [%X]\r\n", _res_ );
    }
}
