/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include <common.h>
#include <yhmemory.h>

extern    BYTE         __MAC[6];
extern    BYTE          __IP[4];

/* Offsets by default are PAGE0 */

#define    CR              0x00
#define    PSTART          0x01
        /* PAR0 Page 1   */
#define    PAR0            0x01
        /* CR9346 Page 3 */
#define    CR9346          0x01
#define    PSTOP           0x02
#define    BNRY            0x03
#define    TSR             0x04
#define    TPSR            0x04
#define    TBCR0           0x05
#define    NCR             0x05
#define    TBCR1           0x06
#define    RTLISR          0x07
        /* CURR Page 1   */
#define CURR            0x07
#define RSAR0           0x08
#define CRDA0           0x08
#define RSAR1           0x09
#define CRDAL           0x09
#define RBCR0           0x0A
#define RBCR1           0x0B
#define RSR	            0x0C
#define RCR             0x0C
#define TCR	            0x0D
#define CNTR0           0x0D
#define DCR             0x0E
#define CNTR1           0x0E
#define IMR             0x0F
#define CNTR2           0x0F
#define RDMAPORT        0X10
#define RSTPORT         0x18

#define      RST                    0x80
#define      RDC                    0x40
#define      OVW                    0x10
#define      PRX                    0x01
#define      PTX                    0x02
#define      TX_START               0x40
#define      RX_START               0x46
#define      RX_STOP                0x60
#define      TCRVAL                 0x00
#define      MAX_TRIES                32
#define      MAX_TX_FRAME_LEN       1518
/*!
  \brief: read a byte from the register
          specified by PORTB.0 - PORTB.5
          corresponding to registers 00-1F
*/
#define read_rtl( regaddr )    \
   DDRA  = 0x00;               \
   PORTA = 0xFF;               \
   PORTB = regaddr;            \
   /* PORTD.6 */               \
   PORTD &= ~0x40;             \
   asm volatile("nop\n\t"::);  \
   asm volatile("nop\n\t"::);  \
   byte_read = PINA;           \
   /* PORTD.6 */               \
   PORTD |= 0x40

#define read_rtl_into( regaddr, x ) \
   read_rtl( regaddr );              \
   x = byte_read

/*!
 \brief: send a byte to register
         specified by PORTB.0 - PORTB.5
         corresponding to registers 00-1F
*/
#define write_rtl(regaddr, regdata) \
    PORTB = regaddr;                \
    DDRA  = 0xFF;                   \
    PORTA = regdata;                \
    /* IOWB PORTD.7 */              \
    PORTD &= ~0x80;                 \
    asm volatile("nop\n\t"::);      \
    asm volatile("nop\n\t"::);      \
    /* IOWB PORTD.7 */              \
    PORTD |= 0x80;                  \
    DDRA = 0x00;                    \
    PORTA = 0xFF

/*!
   \brief: handl_overrun dumps all data and is almost
    equivalentto init_rtl8019AS except for
    some parts
   \note: assumes _res_ is declared
          assumes byte_read is declared
*/
#define handl_overrun               \
    printf( "\r\n OVERRUN \r\n" );  \
    read_rtl(CR);                   \
    write_rtl(CR,    0x21     );    \
    _delay_ms(2);                   \
    write_rtl(RBCR0, 0x00     );    \
    write_rtl(RBCR1, 0x00     );    \
    if( byte_read & 0x04 )          \
    {                               \
        read_rtl(RTLISR);           \
        if( (byte_read & 0x02) ||   \
            (byte_read & 0x08) )    \
            byte_read = 0;          \
        else                        \
            byte_read = 1;          \
    }                               \
    write_rtl(TCR ,  0x02     );    \
    write_rtl(CR  ,  0x22     );    \
    write_rtl(BNRY,  RX_START );    \
    write_rtl(CR  ,  0x62     );    \
    write_rtl(CURR,  RX_START );    \
    write_rtl(CR  ,  0x22     );    \
    write_rtl(RTLISR ,  0x10  );    \
    write_rtl(TCR ,  0x00     );    \
    if( byte_read )                 \
        write_rtl( CR, 0x26 );      \
    write_rtl( RTLISR, 0xFF );      \
    _res_ = RTL_DRV_OVERRUN

#define poll( X, Y ) (PIN##X & Y)

/*!
   \brief:Poll ISR
   check overrun and if any errors set
   _res_ to error OK other wise.
   \note: assumes _res_ is declared.
          assumes byte_read is declared
   \example: while (1) {
                 check_for_incoming_pkt;
                 if( IS_OK )
                 {   // we have an error
                     // free pkt
                     process_packet;
                }
                do_other_useful_stuff;
             }
*/
#define RXE 0x04

extern BYTE last_isr;
#define check_for_incoming_pkt                 \
    /* PORTD and INT0 */                       \
    _res_ = ERR_STATE;                         \
    write_rtl(CR, 0x22);                       \
    byte_read = 0;                             \
    read_rtl(RTLISR);                          \
    if( last_isr != byte_read )                \
    {                                          \
        printf( "ISR CHANGED from"             \
                 "[%X] to [%X]\r\n",           \
              last_isr, byte_read );           \
        last_isr = byte_read;                  \
    }                                          \
    if( byte_read & RXE )                      \
    {                                          \
        write_rtl( RTLISR, byte_read & ~RXE ); \
        printf( "reset to [%X] \r\n",          \
                byte_read & ~RXE );            \
    }                                          \
    if( byte_read & OVW )                      \
    {                                          \
        handl_overrun;                         \
    }                                          \
    if( byte_read & PRX )                      \
        _res_ = OK

#define ETH_BCAST "\xFF\xFF\xFF\xFF\xFF\xFF"
#define ARP_IP_OFFSET 38
RESULT init_RTL8019AS( void );
RESULT get_frame( BYTE**, SHORT* );
RESULT snd_packet( BYTE*, SHORT );
void show_regs( void );
