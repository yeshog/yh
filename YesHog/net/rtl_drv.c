/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include "rtl_drv.h"
BYTE last_isr;
extern BYTE __MAC[ 6 ];
extern BYTE __IP [ 4 ];
extern BYTE __PEER_IP[ 4 ];
extern BYTE __PEER_MAC[ 6 ];
extern SHORT __MYPORT;
extern SHORT __MBUF[MAX_MBUF_SZ];

RESULT init_RTL8019AS(void)
{
    DECLARE( BYTE, byte_read, 0 );
    DECLARE( BYTE, num_tries, 0 );

    /* PORTA data lines = input */
    DDRA  = 0x00;
    PORTA = 0xFF;

    /* clear address lines
         RTL8019AS <--- SA0 --- PB0 ---> AVR
                   <--- SA1 --- PB1 --->
                   ...
                   <--- SA4 --- PB4 --->
 
        PORTB is for the register table 00 - 1F
    */
    DDRB  = 0xFF;
    PORTB = 0x00;

    /* PORTC is not connected */
    DDRC  = 0xFF;

    /* setup IOW, IOR, EEPROM,RXD,TXD,CTS,LE */
    DDRD  = 0xFA;
    PORTD = 0x05;

    /* To prevent the RTL8019AS from expecting data from an
       external EEPROM at startup, we tell the RTL8019AS that
       no EEPROM device exists by taking the RTL8019AS’s EEDO
       (EEPROM Data Output) line low and leaving it low forever
      PORTD.5 */
    PORTD &= ~0x20;

    /* Disable IOW <-> PORTD.7
               IOR <-> PORTD.6
               RST <-> PORTD.4
       PORTD = 0x80|0x40|0x10
    */
    PORTD |= 0xD0;

    /* delay at least 1.6ms */
    _delay_ms(4);

    /* disable reset line */
    PORTD &= ~0x10;
 
    /* read contents of reset port */
    read_rtl(RSTPORT);

    /* Do a soft reset */
    write_rtl(RSTPORT, byte_read);

    /* give it time */
    _delay_ms(10);

    /* check for good soft reset */
    read_rtl(RTLISR);

    if(!(byte_read & RST))
    {
        while(1)
        {
            printf("RTL8019AS INIT FAILED!\r\n");
            _delay_ms(1000);
            num_tries++;
            if( num_tries > MAX_TRIES )
                return RTL_DRV_INIT_FAILED;
        }
    }

    /* stop the NIC, abort DMA, page 0 */
    write_rtl(CR, 0x21);       // 
    /* hope in/out pkts dumped */
    _delay_ms(4);

     /*
                          DCR
        | 7 | 6   | 5   | 4   | 3  | 2   | 1   | 0   |
        | - | FT1 | FT0 | ARM | LS | LAS | BOS | WTS |
        | 0 | 1   | 0   | 1   | 1  | 0   | 0   | 0   |
        WTS Word Transfer Select( 0 ) = 8 bit mode
        LS LoopBack Select( 1 ) = Normal operation
        ARM Auto-Initialize Remote( 1 ) = begin read
    */
    write_rtl(DCR, 0x58);

    /* Initialize Remote Byte Ct Regs */
    write_rtl(RBCR0,0x00);
    write_rtl(RBCR1,0x00);

    /*
       The RCR (Receiver Configuration Register)
       determines what packets to accept and
       whether or not to store them in the RTL8019AS’s
       receive queue.

                          RCR
        | 7 | 6 | 5   | 4   | 3  | 2  | 1  | 0   |
        | - | - | MON | PRO | AM | AB | AR | SEP |
        | 0 | 0 | 0   | 0   | 0  | 1  | 0  | 0   |

        AB Accept Broadcast (1)
        AM Accept Multicast (0)
        AR Accept Runt Pkts (0)
        MON Monitor enable buffering for valid frames
        SEP save errored pkts (0)
        PRO Promiscious mode
    */
    write_rtl(RCR, 0x04);

    /* Transmit page start address = 0x40
       translating to 0x4000 since we deal
       with 256 byte pages */
    write_rtl(TPSR, TX_START);

    /* Transmit Configuration Register
                          TCR
        | 7 | 6 | 5 | 4    | 3   | 2   | 1   | 0   |
        | - | - | - | OFST | ATD | LB1 | LB0 | CRC |
        | 0 | 0 | 0 | 0    | 0   | 0   | 1   | 0   |
        OFST Collision Offset Enable.
        Auto Transmit Disable. 0: normal operation
                               1: reception of multicast 
                                  address hashing to bit 62
                                 disables transmitter,
                                  reception of multicast address
                           hashing to bit 63 enables transmitter.

        LB1 | LB0 | Mode | Remark
        0   | 0   | 0    | Normal
        0   | 1   | 1    | Internal Loopback
        1   | 0   | 2    | External Loopback
        1   | 1   | 3    | External Loopback

        CRC | Mode | CRC Generator | CRC Check
        0   | 0    | 1             | 1
        1   | 0    | 0             | 1
        0   | 1,2,3| 1             | 0
        1   | 1,2,3| 0             | 1
    */
    write_rtl(TCR, 0x02);

    /* Upper bound 0x6000
       Lower bound 0x4000
       TX page sz  0x0600
       -----------------
       TX start    0x4000
       RX start    0x4600
    */ 
    write_rtl(PSTART, RX_START);
    write_rtl(BNRY  , RX_START);
    write_rtl(PSTOP , RX_STOP );

    /* Command Register
                          CR
        | 7   | 6   | 5   | 4    | 3   | 2   | 1   | 0   |
        | PS1 | PS0 | RD2 | RD1  | RD0 | TXP | STA | STP |
        | 0   | 1   | 1   | 0    | 0   | 0   | 0   | 1   |
        PS1, PS0 Page Select (1, 1 = RTL Configuration)

        RD2 | RD1 | RD0 |Function
        0   | 0   | 0   | Not allowed
        0   | 0   | 1   | Remote Read
        0   | 1   | 0   | Remote Write
        0   | 1   | 1   | Send Packet
        1   | *   | *   | Abort/Complete remote DMA

        TXP (1) Must be set to transmit packet
        STA | STP | Function
        1   | 0   | Start Command
        0   | 1   | Stop Command
    */
    write_rtl(CR, 0x61);
    write_rtl(CURR, RX_START);

    /* MAC address register Page1/R/W */
    write_rtl(PAR0    , __MAC[ 0 ] );
    write_rtl(PAR0 + 1, __MAC[ 1 ] );
    write_rtl(PAR0 + 2, __MAC[ 2 ] );
    write_rtl(PAR0 + 3, __MAC[ 3 ] );
    write_rtl(PAR0 + 4, __MAC[ 4 ] );
    write_rtl(PAR0 + 5, __MAC[ 5 ] );

    /* Remote Write, Start */
    write_rtl(CR, 0x22);

    /* Interrupt Status Register
                          ISR
        | 7   | 6   | 5   | 4    | 3   | 2   | 1   | 0   |
        | RST | RDC | CNT | OVW  | TXE | RXE | PTX | PRX |
        | 1   | 1   | 1   | 1    | 1   | 1   | 1   | 1   |
        RST Reset
        RDC Remote DMA Complete
        CNT MSB of network counters set
        OVW Recv buffer exhausted
        TXE Transmit Error (collisions)
        RXE Recv Error due to CRC, Frame Alignment, Missed pkt
        PTX  Packet Transmitted with no errors
        PRX Packet Received with no errors
    */
    write_rtl(RTLISR, 0xFF);

    /* Mask interrupts keeping only OVW, PRX */
    write_rtl(IMR, 0x11);

    /* Normal Operation Hooray! */
    write_rtl(TCR, 0x00);
    return OK;
}

/*!
    \brief: get an ethernet frame from the rtl buffer
            ring
    \param1: [OUT] packet allocated to incoming frame sz
             caller *MUST* free packet after use
    \param2: [OUT] length of packet received
    \return: OK if successful, error/state if any
*/
RESULT get_frame( BYTE** pkt, SHORT* len )
{
    DECLARE( BYTE,   byte_read, 0 );
    DECLARE( SSHORT, rxlen,     0 );
    DECLARE( BYTE,   nxt_pg,    0 );
    DECLARE( BYTE,   status,    0 );
    DECLARE( SSHORT, memfree,   0 );
    DECLARE( SHORT,  i,         0 );
    DECLARE( BYTE*,  packet, NULL );
    DECLARE( RESULT, _res_,    OK );
    DECLARE( BYTE,  curr,       0 );
    DECLARE( BYTE,  bnry,       0 );
    write_rtl(CR, 0x62);
    read_rtl_into( CURR, curr  );
    write_rtl(CR, 0x22);
    read_rtl_into( BNRY, bnry  );
    read_rtl_into(RTLISR, status);
    /* debug */
    printf( "CURR [%X] BNRY [%X] ISR[%X]"
            " MEM[%d]\r\n", curr, bnry, status,
            yh_check_free(0) );
    /* end debug */
    /* clear the ISR bit since we are processing it */
    write_rtl( RTLISR, status & ~PRX );
    if( curr == bnry )
    {
        return RTL_NO_PKT;
    }
    if( bnry >= RX_STOP || bnry < RX_START )
    {
        write_rtl( BNRY, RX_START );
        write_rtl( CR  , 0x62     );
        write_rtl( CURR, RX_START );
        write_rtl( CR  , 0x22     );
        return RTL_BNRY_SKEW;
    }
    /* Get the page header */
    write_rtl(RBCR0, 4);
    write_rtl(RBCR1, 0);
    write_rtl(RSAR0, 0);
    write_rtl(RSAR1, bnry);
    write_rtl( CR, 0x0A );
    /* status */
    read_rtl_into( RDMAPORT, status  );
    /* Next page */
    read_rtl_into( RDMAPORT, nxt_pg  );
    /* LSB first */
    read_rtl_into( RDMAPORT, rxlen  );
    /* MSB second */
    read_rtl( RDMAPORT );
    rxlen |= ( byte_read << SIZEOF_BYTE );
    /* end DMA */
    write_rtl( CR, 0x22 );
    /* check remote data complete for a
       few iterations */
    i = 0;
    do
    {
        read_rtl( RTLISR );
        i++;
    } while( !(byte_read & RDC) && i < 32 );
    write_rtl( RTLISR, byte_read & ~RDC);

    /*debug */
    printf( "status [%X] next_pg [%X] rxlen[%d] \r\n",
                status, nxt_pg, rxlen );
    /* end debug */

    /* is nxt page is valid? ie. from 0x46 to 0x60 */
    if( ( nxt_pg >= RX_STOP) || (nxt_pg < RX_START) )
    {
        printf( "nxt_pg [%X] invalid\r\n", nxt_pg );
        _res_ = RTL_NXT_PG_INVALID;
        goto done;
    }
    /* Now get the real length */
    rxlen -= 4;
    if( rxlen < MIN_FRAME_LEN )
    {
        printf( "rxlen[%d] < MIN_FRAME_LEN\r\n", rxlen );
        _res_ = RTL_DRV_RX_FRAME_TOO_SMALL;
        goto done;
    }
    *len = rxlen;
    /*
    memfree = yh_check_free( rxlen );

    // rxlen is len of rx frame
    if ( rxlen > MAX_RX_FRAME_LEN ||
         memfree < 0 )
    {
        printf( "Error Check memory [%d] RX len [%d]\r\n",
                memfree, rxlen );
        _res_ = ( memfree < 0 ) ?
                RTL_DRV_RX_FRAME_TOO_BIG:
                RTL_DRV_OUT_OF_MEMORY;
        goto done;
    }

    //Read packet to remote DMA
    packet = yh_calloc( rxlen, 1 );
    if( packet == NULL )
    {
        printf( "Out of memory rxlen [%d] [%d]\r\n",
                                   rxlen, memfree );
        _res_ =  RTL_DRV_OUT_OF_MEMORY;
        goto done;
    }
     */
    /* so we can distinguish packet = NULL and valid */
    packet = __MBUF;
    *pkt   = packet;
    write_rtl( RBCR0, rxlen         );
    write_rtl( RBCR1, ( rxlen >> 8 ));
    write_rtl( CR   , 0x0A          );
    for( i = 0; i < rxlen; ++i )
    {
        read_rtl_into( RDMAPORT, packet[i] );
    }
    printf( "Done reading packet of len [%d] into remote DMA\r\n",
            rxlen );
    /* end the DMA operation */
    //write_rtl( CR, 0x22 );
    i = 0;
    while( !(byte_read & RDC) && i < 32 )
    {
        read_rtl(RDMAPORT);
        /* discard */
        printf( " %X ", byte_read );
        read_rtl( RTLISR );
        i++;
    };
    /* finish up */
    write_rtl( RTLISR, byte_read & ~RDC );
    printf( "Skipped\r\n" );
    i = 0;
    if( memcmp( packet, ETH_BCAST, 6 ) == 0 )
    {
        i = 1;
    }
    if( i && rxlen > 60 )
    {
        //yh_free( packet, rxlen );
        _res_ = RTL_BROADCAST_BASTARD_PACKET;
        goto done;
    }
    /* This REALLY does not belong here YIKES
     * I am hereby mr disgusty dino-brain */
    if( i && memcmp( __IP,
        packet + ARP_IP_OFFSET, 4 ) != 0 )
    {
        /* If this is a broadcast packet
         * it better be arp and it better be
         * me. And most importantly dont hurt
         * my eyes with stray packets
         */
        //yh_free( packet, rxlen );
        _res_ = RTL_BROADCAST_IP_MAN;
        goto done;
    }
    printf( "get_frame result OK\r\n" );
    _res_ = OK;
done:
    write_rtl( BNRY, nxt_pg );
    return _res_;
}

/*!
    \brief: send an ethernet frame
    \param1: [IN] packet/data to be sent
    \param2: [INOUT] Status
    \return: OK if successful, error/state if any
*/
RESULT snd_packet( BYTE* packet, SHORT len )
{
    DECLARE( BYTE, byte_read, 0 );
    DECLARE( SHORT, i,        0 );

    if( !packet || len > MAX_TX_FRAME_LEN )
    {
        /* should never happen */
        return (packet)?
              RTL_DRV_TX_FRAME_TOO_BIG :
                    RTL_DRV_NULL_TX_PKT;
    }
    if( len < 60 )
    {
        return RTL_DRV_TX_RUNT_PKT;
    }

    /* RD2 and STA */
    write_rtl( CR, 0x22 );
    /* wait if a packet is being xmitted */
    do
    {
        /* while TXP is set */
        read_rtl(CR);
    } while( byte_read & 0x04 );

    /* TX start address */
    write_rtl( TPSR, TX_START );
    /*
      RSAR0-1 xmit buffer addresses
      and clear ISR
    */
    write_rtl( RSAR0, 0x00    );
    write_rtl( RSAR1, 0x40    );
    read_rtl( RTLISR );

    /* debug */
    printf( "TX [%u] RBCR0 [%X] RBCR1 [%X] ISR [%X]",
             len, len & 0xFF, (len >> 8 ) & 0xFF, byte_read );
    /* end debug */

    /* load remote and xmit byte count registers */
    write_rtl( RBCR0, ( len & 0xFF ) );
    write_rtl( RBCR1,  (len >> 8 ) & 0xFF );
    write_rtl( TBCR0, ( len & 0xFF ) );
    write_rtl( TBCR1, ( len >> 8 ) & 0xFF );

    /* RD1, STA = RemoteWrite Start */
    write_rtl( CR,    0x12    );
    for( ; i < len; i++ )
    {
        write_rtl( RDMAPORT, packet[i] );
    }
    /* tell rtl to kick the packet to the wire */
    write_rtl( CR, 0x24 );

    i = 0;
    do
    {
        read_rtl( RTLISR );
        i++;
        if( i > 32 )
        {
            break;
        }
    } while( !( byte_read & RDC ) );
    write_rtl( RTLISR, byte_read & ~RDC);
    write_rtl( RTLISR, byte_read & ~PTX);
    printf( ". TX complete i[%d] [%X]\r\n", i, byte_read );
    return OK;
}

/*!
    \brief: Show values of the Realtek registers
            The most important rtl debugging
            function
*/
void show_regs()
{
    DECLARE( BYTE, i, 0 );
    DECLARE( BYTE, v, 0 );
    DECLARE( BYTE, byte_read, 0 );

    write_rtl(CR,0x21);
    printf("\r\n");
    printf("Realtek 8019AS Register Dump\r\n");
    printf("Pg0 Pg1 Pg2 Pg3\r\n");

    for( ; i < 16; ++i )
    {
        printf(  "%02X ",  i );
        write_rtl( CR, 0x21 );
        read_rtl_into( i, v );
        printf(  "%02X ",  v );
        write_rtl( CR, 0x61 );
        read_rtl_into( i, v );
        printf(  "%02X ",  v );
        write_rtl( CR, 0xA1 );
        read_rtl_into( i, v );
        printf(  "%02X ",  v );
        write_rtl( CR, 0xE1 );
        read_rtl_into( i, v );
        printf(  "%02X",  v );
        printf("\r\n");
    }
}
