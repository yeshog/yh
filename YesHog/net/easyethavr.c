//////////////////////////////////////////////////////////////////////
// REALTEK RTL8019AS DRIVER FOR AVR ATMEGA16
// PACKET WHACKER ENABLED
// Author: Fred Eady
// Company: EDTP Electronics
// Version: 1.2
// Date: 08/19/03
// Description: ARP, PING, ECHO and LCD Control, TCP, UDP
//////////////////////////////////////////////////////////////////////
//******************************************************************
//*	PORT MAP
//******************************************************************
// PORT A = rtldata - data bus LCD,RTL8019 and AVR
//  0	SD0 - LCD D4
//  1   SD1 - LCD D5
//  2   SD2 - LCD D6
//  3   SD3 - LCD D7
//  4   SD4 
//  5   SD5 
//  6   SD6
//  7   SD7
// PORT B
//  0	SA0 
//  1   SA1 
//  2   SA2 
//  3   SA3 
//  4   SA4 
//  5   
//  6   
//  7   
// PORT C 
//  0	E
//  1   RS 
//  2   TCK
//  3   TMS
//  4   TDO
//  5   TDI
//  6   BL
//  7   rst_pin
// PORT D
//  0	RXD
//  1   TXD
//  2   INT0
//  3   EESK
//  4   EEDI
//  5   EEDO
//  6   ior_pin
//  7   iow_pin

#include <avr/io.h>
#include <string.h>
#include <stdio.h>
#include <util/delay.h>
#define  esc   0x1B
//******************************************************************
//*	BAUD RATE NUMBERS FOR UBRR
//******************************************************************
#define  b9600  47		// 7.3728MHz clock
#define	 b19200 23
#define	 b38400 11
#define	 b57600 7
#define FOSC 16000000
#define BAUD 9600
#define MYUBRR FOSC/16/BAUD-1
uint8_t uart_getchar( void );
int uart_putchar(char c, FILE *stream);
static FILE mystdout =
           FDEV_SETUP_STREAM(uart_putchar, NULL,
                             _FDEV_SETUP_WRITE);
//******************************************************************
//*	FUNCTION PROTOTYPES
//******************************************************************

void init_USART(void);
void show_aux_packet(void);
void dump_header(void);
void readwrite(void);
void bin2hex(unsigned char binchar);
void show_regs(void);
void show_packet(void);
void cls(void);
//void application_code(void);
void tcp(void);
void assemble_ack(void);
void write_rtl(unsigned int regaddr, unsigned int regdata);
void read_rtl(unsigned int regaddr);
void get_frame(void);
void setipaddrs(void);
void cksum(void);
void echo_packet(void);
void send_tcp_packet(void);
void arp(void);
void icmp(void);
void udp(void);
//******************************************************************
//*	TELNET SERVER BANNER STATEMENT CONSTANT
//******************************************************************
char const telnet_banner[] = {"\r\nEasy Ethernet AVR>"};
//******************************************************************
//*	IP ADDRESS DEFINITION
//*   This is the Ethernet Module IP address.
//*   You may change this to any valid address.
//******************************************************************
unsigned char MYIP[4] = { 192,168,1,28 };
//******************************************************************
//*	HARDWARE (MAC) ADDRESS DEFINITION
//*   This is the Ethernet Module hardware address.
//*   You may change this to any valid address.
//******************************************************************
char MYMAC[6] = { 0,0,'Y','O','G','I' };
//******************************************************************
//*	Receive Ring Buffer Header Layout
//*   This is the 4-byte header that resides infront of the
//*   data packet in the receive buffer.
//******************************************************************
unsigned char  pageheader[4];
#define  enetpacketstatus     0x00
#define  nextblock_ptr        0x01
#define	 enetpacketLenL		  0x02
#define	 enetpacketLenH		  0x03
//******************************************************************
//*	Ethernet Header Layout
//******************************************************************
unsigned char  packet[96];       //50 bytes of UDP data available
#define	enetpacketDest0	   0x00  //destination mac address
#define	enetpacketDest1	   0x01
#define	enetpacketDest2	   0x02
#define	enetpacketDest3	   0x03
#define	enetpacketDest4	   0x04
#define	enetpacketDest5	   0x05
#define	enetpacketSrc0	   0x06  //source mac address
#define	enetpacketSrc1	   0x07
#define	enetpacketSrc2	   0x08
#define	enetpacketSrc3	   0x09
#define	enetpacketSrc4	   0x0A
#define	enetpacketSrc5	   0x0B
#define	enetpacketType0	   0x0C  //type/length field
#define	enetpacketType1	   0x0D
#define  enetpacketData    0x0E  //IP data area begins here
//******************************************************************
//*	ARP Layout
//******************************************************************
#define	arp_hwtype			   0x0E
#define	arp_prtype			   0x10
#define	arp_hwlen			   0x12
#define	arp_prlen			   0x13
#define	arp_op				   0x14
#define	arp_shaddr			   0x16   //arp source mac address
#define	arp_sipaddr			   0x1C   //arp source ip address
#define	arp_thaddr			   0x20   //arp target mac address
#define	arp_tipaddr			   0x26   //arp target ip address
//******************************************************************
//*	IP Header Layout
//******************************************************************
#define	ip_vers_len			   0x0E	//IP version and header length
#define	ip_tos				   0x0F	//IP type of service
#define	ip_pktlen			   0x10	//packet length
#define	ip_id				   0x12	//datagram id
#define	ip_frag_offset		   0x14	//fragment offset
#define	ip_ttl				   0x16	//time to live
#define	ip_proto			   0x17	//protocol (ICMP=1, TCP=6, UDP=11)
#define	ip_hdr_cksum		   0x18	//header checksum
#define	ip_srcaddr			   0x1A	//IP address of source
#define	ip_destaddr			   0x1E	//IP addess of destination
#define	ip_data				   0x22	//IP data area
//******************************************************************
//*	TCP Header Layout
//******************************************************************
#define	TCP_srcport			   0x22	//TCP source port
#define	TCP_destport   	   	   0x24	//TCP destination port
#define	TCP_seqnum  	       0x26	//sequence number
#define	TCP_acknum	           0x2A	//acknowledgement number
#define	TCP_hdrflags		   0x2E	//4-bit header len and flags
#define	TCP_window			   0x30	//window size
#define	TCP_cksum		       0x32	//TCP checksum
#define	TCP_urgentptr   	   0x34	//urgent pointer
#define TCP_data               0x36  //option/data
//******************************************************************
//*	TCP Flags
//*   IN flags represent incoming bits
//*   OUT flags represent outgoing bits
//******************************************************************
#define  FIN_IN               (packet[TCP_hdrflags+1] & 0x01)
#define  SYN_IN               (packet[TCP_hdrflags+1] & 0x02)
#define  RST_IN               (packet[TCP_hdrflags+1] & 0x04)
#define  PSH_IN               (packet[TCP_hdrflags+1] & 0x08)
#define  ACK_IN               (packet[TCP_hdrflags+1] & 0x10)
#define  URG_IN               (packet[TCP_hdrflags+1] & 0x20)
#define  FIN_OUT              packet[TCP_hdrflags+1] |= 0x01 //00000001
#define  SYN_OUT              packet[TCP_hdrflags+1] |= 0x02 //00000010
#define  RST_OUT              packet[TCP_hdrflags+1] |= 0x04 //00000100
#define  PSH_OUT              packet[TCP_hdrflags+1] |= 0x08 //00001000
#define  ACK_OUT              packet[TCP_hdrflags+1] |= 0x10 //00010000
#define  URG_OUT              packet[TCP_hdrflags+1] |= 0x20 //00100000
//******************************************************************
//*	Port Definitions
//*   This address is used by TCP and the Telnet function.
//*   This can be changed to any valid port number as long as
//*   you modify your code to recognize the new port number.
//******************************************************************
#define  MY_PORT_ADDRESS      0x1F98  // 8088 DECIMAL
//******************************************************************
//*	IP Protocol Types
//******************************************************************
#define	PROT_ICMP			  0x01
#define	PROT_TCP			  0x06
#define	PROT_UDP			  0x11
//******************************************************************
//*	ICMP Header
//******************************************************************
#define	ICMP_type			   ip_data
#define	ICMP_code			   ICMP_type+1
#define	ICMP_cksum			   ICMP_code+1
#define	ICMP_id				   ICMP_cksum+2
#define	ICMP_seqnum			   ICMP_id+2
#define ICMP_data              ICMP_seqnum+2
//******************************************************************
//*	UDP Header
//;******************************************************************
#define	UDP_srcport			   ip_data
#define	UDP_destport		   UDP_srcport+2
#define	UDP_len				   UDP_destport+2
#define	UDP_cksum			   UDP_len+2
#define	UDP_data			   UDP_cksum+2
//******************************************************************
//*	REALTEK CONTROL REGISTER OFFSETS
//*   All offsets in Page 0 unless otherwise specified
//******************************************************************
#define CR		 	0x00
#define PSTART		0x01
#define PAR0      	0x01    // Page 1
#define CR9346    	0x01    // Page 3
#define PSTOP		0x02
#define BNRY		0x03
#define TSR			0x04
#define TPSR		0x04
#define TBCR0		0x05
#define NCR			0x05
#define TBCR1		0x06
#define ISR			0x07
#define CURR		0x07   // Page 1
#define RSAR0		0x08
#define CRDA0		0x08
#define RSAR1		0x09
#define CRDAL		0x09
#define RBCR0		0x0A
#define RBCR1		0x0B
#define RSR			0x0C
#define RCR			0x0C
#define TCR			0x0D
#define CNTR0		0x0D
#define DCR			0x0E
#define CNTR1		0x0E
#define IMR			0x0F
#define CNTR2		0x0F
#define RDMAPORT  	0X10
#define RSTPORT   	0x18
//******************************************************************
//*	RTL8019AS INITIAL REGISTER VALUES
//******************************************************************
#define rcrval		0x04
#define tcrval		0x00
#define dcrval		0x58    // was 0x48
#define imrval		0x11    // PRX and OVW interrupt enabled
#define txstart   	0x40
#define rxstart   	0x46
#define rxstop    	0x60
//******************************************************************
//*	RTL8019AS DATA/ADDRESS PIN DEFINITIONS
//******************************************************************
#define  rtladdr    PORTB
#define  rtldata    PORTA
#define  tortl      DDRA = 0xFF 	
#define  fromrtl    DDRA = 0x00 
//******************************************************************
//*	RTL8019AS 9346 EEPROM PIN DEFINITIONS
//******************************************************************
#define  EESK        0x08 //PORTD3 00001000
#define  EEDI        0x10 //PORTD4 00010000
#define  EEDO        0x20 //PORTD5 00100000
//******************************************************************
//*	RTL8019AS ISR REGISTER DEFINITIONS
//******************************************************************
#define  RST         0x80 //1000000
#define  RDC         0x40 //0100000
#define  OVW         0x10 //0001000
#define  PRX         0x01 //0000001
//******************************************************************
//*	AVR RAM Definitions
//******************************************************************
unsigned char aux_data[20];            //tcp received data area
unsigned char *addr,flags,last_line;
unsigned char byteout,byte_read,data_H,data_L;
unsigned char high_nibble, low_nibble, high_char, low_char,resend;
unsigned int i,txlen,rxlen,chksum16,hdrlen,tcplen,tcpdatalen_in;
unsigned int tcpdatalen_out,ISN,portaddr,ip_packet_len,cntr;
unsigned long hdr_chksum,my_seqnum,client_seqnum,incoming_ack,expected_ack;
//******************************************************************
//*	Flags
//******************************************************************
#define synflag 0x01 //00000001
#define	finflag	0x02 //00000010
#define hexflag 0x04 //00000100
#define synflag_bit flags & synflag
#define finflag_bit flags & finflag
#define hexflag_bit flags & hexflag
//******************************************************************
//*	  PORT and LCD DEFINITIONS
//******************************************************************
#define databus	   PORTA
#define addrbus    PORTB													
#define eeprom	   PORTD
#define iorwport   PORTD
#define lcdcntrl   PORTC
#define cport	   PORTC
#define resetport  PORTD
#define nop		   NOP()
#define BL 		   0x40
#define RS 		   0x02
#define E  		   0x01  
#define BLon       lcdcntrl |= BL
#define BLoff	   lcdcntrl &= ~BL
#define clrRS	   lcdcntrl &= ~RS
#define setRS	   lcdcntrl |= RS
#define clrE	   lcdcntrl &= ~E
#define setE	   lcdcntrl |= E
				   
#define lcdcls	   lcd_send_byte(0,0x01)
#define	line1	   lcd_gotoxy(1,1)
#define	line2	   lcd_gotoxy(2,1)
#define	line3	   lcd_gotoxy(3,1)
#define	line4	   lcd_gotoxy(4,1)

unsigned char LCD_INIT_STRING[5] = {0x28,0x08,0x01,0x06,0x0E};
unsigned char msg_initfail[] = "INIT FAILED";
//******************************************************************
//*	RTL8019AS PIN DEFINITIONS
//******************************************************************
#define  ior_pin     0x40 //PORTD6 01000000
#define  iow_pin     0x80 //PORTD7 10000000
#define  rst_pin     0x10 //PORTD4 00010000
#define  INT0_pin    0x04 //PORTD2 00000100
#define  LE_pin		 0x08 //PORTD3 00001000
//******************************************************************
//*	RTL8019AS PIN MACROS
//******************************************************************
#define set_ior_pin iorwport |= ior_pin
#define clr_ior_pin iorwport &= ~ior_pin
#define set_iow_pin iorwport |= iow_pin
#define clr_iow_pin iorwport &= ~iow_pin
#define set_rst_pin resetport |= rst_pin
#define clr_rst_pin resetport &= ~rst_pin
#define set_le_pin  iorwport |= LE_pin
#define clr_le_pin  iorwport &= ~LE_pin

#define set_cport_0 cport |= 0x01
#define set_cport_1 cport |= 0x02
#define set_cport_2 cport |= 0x04
#define set_cport_3 cport |= 0x08
#define set_cport_4 cport |= 0x10
#define set_cport_5 cport |= 0x20
#define set_cport_6 cport |= 0x40
#define set_cport_7 cport |= 0x80

#define clr_cport_0 cport &= ~0x01
#define clr_cport_1 cport &= ~0x02
#define clr_cport_2 cport &= ~0x04
#define clr_cport_3 cport &= ~0x05
#define clr_cport_4 cport &= ~0x10
#define clr_cport_5 cport &= ~0x20
#define clr_cport_6 cport &= ~0x40
#define clr_cport_7 cport &= ~0x80


#define clr_EEDO eeprom &= ~EEDO
#define set_EEDO eeprom |= EEDO

#define clr_synflag flags &= ~synflag
#define set_synflag flags |= synflag
#define clr_finflag flags &= ~finflag
#define set_finflag flags |= finflag

#define clr_hex flags &= ~hexflag
#define set_hex flags |= hexflag

#define  set_packet32(d,s) packet[d] = make8(s,3);   \
                           packet[d+1] = make8(s,2); \
                           packet[d+2] = make8(s,1); \
                           packet[d+3]= make8(s,0); 
						   
#define make8(var,offset)	(var >> (offset * 8)) & 0xFF
#define	make16(varhigh,varlow)	((varhigh & 0xFF)* 0x100) + (varlow & 0xFF)
#define make32(var1,var2,var3,var4) \
		((unsigned long)var1<<24)+((unsigned long)var2<<16)+ \
		((unsigned long)var3<<8)+((unsigned long)var4)
		
//******************************************************************
//*	Application Code
//*   Your application code goes here.
//*   This particular code toggles the LED on PORT A bit 4 using
//*   Telnet.
//******************************************************************
/*
void application_code()
{
   int i,j;

   ++cntr;

   if(aux_data[0] != 0x0A)
      tcpdatalen_out = tcpdatalen_in;
   if(aux_data[0] == 0x0A)
   {
      tcpdatalen_out = 0x00;
      clr_hex;
   }
   if(hexflag)
   {
	 if(aux_data[0] >= '0' && aux_data[0] <= '9')
       aux_data[0] -= 0x30;
	 else if(aux_data[0] >= 'A' && aux_data[0] <= 'F')
	   aux_data[0] -= 0x37;
	 else if(aux_data[0] >= 'a' && aux_data[0] <= 'f')
	   aux_data[0] -= 0x67;
     else
     {
	   cntr = 0x00;
       clr_hex;
     }

     if(cntr == 1)
       byteout = aux_data[0] << 4;
	 if(cntr == 2)
     {
       byteout |= aux_data[0] & 0x0F;
	   DDRA = 0xFF;            //tocreg;
       PORTA = byteout;		  //cregdata = byteout;
       //latchdata;
       clr_hex;
	   printf("Byte Latched = %x\r\n",byteout);
     }
   }
   if(aux_data[0] == '*')
   {
   	set_hex;
    cntr=0;
   }

   if (aux_data[0] == 0x0D)
      {
         j = sizeof(telnet_banner);
	     for(i=0;i<j;++i)
          packet[TCP_data+i] = telnet_banner[i];
         tcpdatalen_out = j;
      }
}*/
/*						   
******************************************************************
*	Application Code
*   Your application code goes here.
*   This particular code echos the incoming Telnet data to the LCD
******************************************************************
void application_code()
{
   
  for(i=0;i<tcpdatalen_in;++i)
  {		
   
   if(aux_data[i] != 0x0A)
      tcpdatalen_out = tcpdatalen_in;
   if(aux_data[i] == 0x0A)
      tcpdatalen_out = 0x00;
	  
   switch (aux_data[i])
   {
    case '~': //throws up a banner message
		
		 strcpy(&aux_data[0],"Telnet is UP!       ");
		 line1; 
		 for (i=0;i<20;++i)
		 	 lcd_send_byte(1,aux_data[i]); 
					 
		 strcpy(&aux_data[0],"216.53.172.209:8088 ");	
		 		 line2;
		 for (i=0;i<20;++i)
		 	lcd_send_byte(1,aux_data[i]); 

		 strcpy(&aux_data[0],"ESC=Clear LCD       ");	
		 		 line3;
		 for (i=0;i<20;++i)
		 	lcd_send_byte(1,aux_data[i]); 

		 strcpy(&aux_data[0],"TAB=New Line        ");	
		 		 line4;
		 for (i=0;i<20;++i)
		  	lcd_send_byte(1,aux_data[i]); 
		 line1;	
 		 break;	
   	case 0x0D:
	     strcpy(&packet[TCP_data],"\r\nEDTP AVR Telnet SERVER>");
         tcpdatalen_out = 25;
         break;
    case 0x1B: //ESC clears the LCD
         last_line = 0; 
	     lcdcls;
         strcpy(&packet[TCP_data],"\r\nEDTP AVR Telnet SERVER>");
         tcpdatalen_out = 25;
	  	 break;	 	
	case 0x09: //TAB takes you to the next LCD line
	     switch (last_line)
		 {
		  case 0x00:
		       line2;
			   last_line = 0x40;
			   break;
		  case 0x40:
		       line3;
			   last_line = 0x14;
			   break;
		  case 0x14:
		  	   line4;
			   last_line = 0x54;
			   break;
		  case 0x54:
		  	   line1;
			   last_line = 0x00;
			   break;
		  default:
		  	   line1;
			   last_line = 0x00;
			   break;
		  }	   	 	   	   	   	 
		  break;
	 default:
	      lcd_send_byte(1,aux_data[i]);
		  break;
	}	  	  
	}
	
 }
 */

uint8_t uart_getchar( void )
{
    /* Wait for data to be received */
    while ( !( UCSR0A & ( 1<<RXC0 ) ) );

    /* Get and return received data from buffer */
    return UDR0;
}

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

//******************************************************************
//*	USART Function
//*   
//******************************************************************
void init_USART()
{
    UBRR0H = (MYUBRR) >> 8;
    UBRR0L = MYUBRR;
    UCSR0B = (1<<RXEN0)|(1<<TXEN0);
    stdout = &mystdout;
} 

//******************************************************************
//*	Perform ARP Response
//*   This routine supplies a requesting computer with the
//*   Ethernet modules's MAC (hardware) address.
//******************************************************************
void arp()
{
   //start the NIC
   write_rtl(CR,0x22);

   //load beginning page for transmit buffer
   write_rtl(TPSR,txstart);

   //set start address for remote DMA operation
   write_rtl(RSAR0,0x00);
   write_rtl(RSAR1,0x40);

   //clear the Interrupts
   write_rtl(ISR,0xFF);

   //load data byte count for remote DMA
   write_rtl(RBCR0,0x3C);
   write_rtl(RBCR1,0x00);

   //do remote write operation
   write_rtl(CR,0x12);

   //write destination MAC address
   for(i=0;i<6;++i)
      write_rtl(RDMAPORT,packet[enetpacketSrc0+i]);

   //write source MAC address
   for(i=0;i<6;++i)
      write_rtl(RDMAPORT,MYMAC[i]);

   //write typelen hwtype prtype hwlen prlen op:
   addr = &packet[enetpacketType0];
   packet[arp_op+1] = 0x02;
   for(i=0;i<10;++i)
      write_rtl(RDMAPORT,*addr++);

   //write ethernet module MAC address
   for(i=0;i<6;++i)
      write_rtl(RDMAPORT,MYMAC[i]);

   //write ethernet module IP address
      for(i=0;i<4;++i)
      write_rtl(RDMAPORT,MYIP[i]);

   //write remote MAC address
   for(i=0;i<6;++i)
      write_rtl(RDMAPORT,packet[enetpacketSrc0+i]);

   //write remote IP address
   for(i=0;i<4;++i)
      write_rtl(RDMAPORT,packet[arp_sipaddr+i]);

   //write some pad characters to fill out the packet to
   //the minimum length
   for(i=0;i<0x12;++i)
      write_rtl(RDMAPORT,0x00);

   //make sure the DMA operation has successfully completed
   byte_read = 0;
   while(!(byte_read & RDC))
       	 read_rtl(ISR);  

   //load number of bytes to be transmitted
   write_rtl(TBCR0,0x3C);
   write_rtl(TBCR1,0x00);

   //send the contents of the transmit buffer onto the network
   write_rtl(CR,0x24);
 }
//******************************************************************
//*	Perform ICMP Function
//*   This routine responds to a ping.
//******************************************************************
void icmp()
{
   //set echo reply
   packet[ICMP_type]=0x00;
   packet[ICMP_code]=0x00;

   //clear the ICMP checksum
   packet[ICMP_cksum ]=0x00;
   packet[ICMP_cksum+1]=0x00;

   //setup the IP header
   setipaddrs();

   //calculate the ICMP checksum
   hdr_chksum =0;
   hdrlen = (make16(packet[ip_pktlen],packet[ip_pktlen+1])) - \
   ((packet[ip_vers_len] & 0x0F) * 4);
   addr = &packet[ICMP_type];
   cksum();
   chksum16= ~(hdr_chksum + ((hdr_chksum & 0xFFFF0000) >> 16));
   packet[ICMP_cksum] = make8(chksum16,1);
   packet[ICMP_cksum+1] = make8(chksum16,0);
   i=0;
   //send the ICMP packet along on its way
   echo_packet();
}
//******************************************************************
//*	UDP Function
//*   This function uses a Visual Basic UDP program to echo the
//*   data back to the VB program and talk to the LCD.
//******************************************************************
void udp()
{
   //port 7 is the well-known echo port
   if(packet[UDP_destport] == 0x00 && packet[UDP_destport+1] ==0x07)
   {
      //build the IP header
      setipaddrs();

      //swap the UDP source and destination ports
      data_L = packet[UDP_srcport];
      packet[UDP_srcport] = packet[UDP_destport];
      packet[UDP_destport] = data_L;

      data_L = packet[UDP_srcport+1];
      packet[UDP_srcport+1] = packet[UDP_destport+1];
      packet[UDP_destport+1] = data_L;

      //calculate the UDP checksum
      packet[UDP_cksum] = 0x00;
      packet[UDP_cksum+1] = 0x00;

      hdr_chksum =0;
      hdrlen = 0x08;
      addr = &packet[ip_srcaddr];
      cksum();
      hdr_chksum = hdr_chksum + packet[ip_proto];
      hdrlen = 0x02;
      addr = &packet[UDP_len];
      cksum();
      hdrlen = make16(packet[UDP_len],packet[UDP_len+1]);
      addr = &packet[UDP_srcport];
      cksum();
      chksum16= ~(hdr_chksum + ((hdr_chksum & 0xFFFF0000) >> 16));
      packet[UDP_cksum] = make8(chksum16,1);
      packet[UDP_cksum+1] = make8(chksum16,0);

      //echo the incoming data back to the VB program
      echo_packet();
   }

   //buttons on the VB GUI are pointed towards port address 5000 decimal
   else if(packet[UDP_destport] == 0x13 && packet[UDP_destport+1] == 0x88);
	  {
      if(packet[UDP_data] == '0')
         //received a "0" from the VB program
         clr_cport_0;
      else if(packet[UDP_data] == '1')
         //received a "1" from the VB program
         set_cport_0;
      else if(packet[UDP_data] == 0x00)
         //received a 0x00 from the VB program
         PORTC = 0x00;
       else if(packet[UDP_data] == 0x01)
         //received a 0x01 from the VB program
         set_cport_1;
      else if(packet[UDP_data] == 0x02)
         //received a 0x02 from the VB program
         set_cport_2;
      else if(packet[UDP_data] == 0x03)
         //received a 0x03 from the VB program
         set_cport_3;
      else if(packet[UDP_data] == 0x04)
         //received a 0x04 from the VB program
         set_cport_4;
	}	 
/*		 
  //LCD UDP application code
   else if(packet[UDP_destport] == 0x13 && packet[UDP_destport+1] == 0x88)
	  {
       	   
	   	 switch (packet[UDP_data])
		 {
		 		case 0:
					 lcdcls;
					 break;
				case 1:
					 line1;
					 break;
			    case 2:
					 line2;
					 break;
			    case 3:
					 line3;
					 break;
			    case 4:
					 line4;
					 break;
				default:
					 lcd_send_byte(1,packet[UDP_data]);
				 				  	 
		}
	  }
*/
}
//******************************************************************
//*	TCP Function
//*   This function uses TCP protocol to act as a Telnet server on
//*   port 8088 decimal.  The application function is called with
//*   every incoming character.
//******************************************************************
void tcp()
{
   int i,j;
   //assemble the destination port address from the incoming packet
   portaddr = make16(packet[TCP_destport],packet[TCP_destport+1]);

   //calculate the length of the data coming in with the packet
   //tcpdatalen_in = incoming packet length - incoming ip header length - 
   //incoming tcp header length
   tcpdatalen_in = (make16(packet[ip_pktlen],packet[ip_pktlen+1]))- \
   ((packet[ip_vers_len] & 0x0F)* 4)-(((packet[TCP_hdrflags] & 0xF0) >> 4) * 4);

   //If an ACK is received and the destination port address is valid 
   //and no data is in the packet
   if(ACK_IN && portaddr == MY_PORT_ADDRESS && tcpdatalen_in == 0x00)
   {
      //assemble the acknowledgment number from the incoming packet
      incoming_ack =make32(packet[TCP_acknum],packet[TCP_acknum+1], \
	   packet[TCP_acknum+2],packet[TCP_acknum+3]);

      //if the incoming packet is a result of session establishment
      if(synflag_bit)
      {
         //clear the SYN flag
         clr_synflag;

         //the incoming acknowledgment is my new sequence number
         my_seqnum = incoming_ack;

		 //send the Telnet server banner
         //limit the character count to 40 decimal
                j = sizeof(telnet_banner);
                for(i=0;i<j;++i)
 				  packet[TCP_data+i] = telnet_banner[i];
         //length of the banner message
         	   tcpdatalen_out = j;
			   
         //send the Telnet server banner
         //limit the character count to 40 decimal
         //strcpy(&packet[TCP_data],"EDTP AVR Telnet SERVER>");
         //length of the banner message
         //tcpdatalen_out = 23;

         //expect to get an acknowledgment of the banner message
         expected_ack = my_seqnum +tcpdatalen_out;

         //send the TCP/IP packet
         send_tcp_packet();
      }
   }

   //if an ack is received and the port address is valid and there is data 
   //in the incoming packet
   if((ACK_IN) && portaddr == MY_PORT_ADDRESS && tcpdatalen_in)
   {
      
      for(i=0;i<tcpdatalen_in;++i)
         //receive the data and put it into the incoming data buffer
         aux_data[i] = packet[TCP_data+i];
		  
      	  //application_code();   
      
      //assemble the acknowledgment number from the incoming packet
      incoming_ack =make32(packet[TCP_acknum],packet[TCP_acknum+1], \
	  packet[TCP_acknum+2],packet[TCP_acknum+3]);

      //check for the number of bytes acknowledged
      //determine how many bytes are outstanding and adjust the outgoing 
	  //sequence number accordingly
      if(incoming_ack <= expected_ack)
         my_seqnum = expected_ack - (expected_ack - incoming_ack);
     
      //my expected acknowledgement number
      expected_ack = my_seqnum +tcpdatalen_out;
      send_tcp_packet();
	  
   }

   //this code segment processes the incoming SYN from the Telnet client
   //and sends back the initial sequence number (ISN) and acknowledges
   //the incoming SYN packet
   if(SYN_IN && portaddr == MY_PORT_ADDRESS)
   {
      tcpdatalen_in = 0x01;
      set_synflag;

      setipaddrs();

      data_L = packet[TCP_srcport];
      packet[TCP_srcport] = packet[TCP_destport];
      packet[TCP_destport] = data_L;

      data_L = packet[TCP_srcport+1];
      packet[TCP_srcport+1] = packet[TCP_destport+1];
      packet[TCP_destport+1] = data_L;

      assemble_ack();

      if(++ISN == 0x0000 || ++ISN == 0xFFFF)
       	 my_seqnum = 0x1234FFFF;

      set_packet32(TCP_seqnum,my_seqnum);

      packet[TCP_hdrflags+1] = 0x00;
      SYN_OUT;
      ACK_OUT;

      packet[TCP_cksum] = 0x00;
      packet[TCP_cksum+1] = 0x00;

      hdr_chksum =0;
      hdrlen = 0x08;
      addr = &packet[ip_srcaddr];
      cksum();
      hdr_chksum = hdr_chksum + packet[ip_proto];
      tcplen = make16(packet[ip_pktlen],packet[ip_pktlen+1]) - \
	  ((packet[ip_vers_len] & 0x0F) * 4);
      hdr_chksum = hdr_chksum + tcplen;
      hdrlen = tcplen;
      addr = &packet[TCP_srcport];
      cksum();
      chksum16= ~(hdr_chksum + ((hdr_chksum & 0xFFFF0000) >> 16));
      packet[TCP_cksum] = make8(chksum16,1);
      packet[TCP_cksum+1] = make8(chksum16,0);
      echo_packet();
   }

   //this code segment processes a FIN from the Telnet client
   //and acknowledges the FIN and any incoming data.
   if(FIN_IN && portaddr == MY_PORT_ADDRESS)
   {
      if(tcpdatalen_in)
      {
         for(i=0;i<tcpdatalen_in;++i)
         {
            aux_data[i] = packet[TCP_data+i];
            //application_code();
         }
      }

      set_finflag;

      ++tcpdatalen_in;

      incoming_ack =make32(packet[TCP_acknum],packet[TCP_acknum+1], \
	  packet[TCP_acknum+2],packet[TCP_acknum+3]);
      if(incoming_ack <= expected_ack)
         my_seqnum = expected_ack - (expected_ack - incoming_ack);

      expected_ack = my_seqnum +tcpdatalen_out;
      send_tcp_packet();

   }
}
//******************************************************************
//*	Assemble the Acknowledgment
//*   This function assembles the acknowledgment to send to
//*   to the client by adding the received data count to the
//*   client's incoming sequence number.
//******************************************************************
void assemble_ack()
{
   client_seqnum=make32(packet[TCP_seqnum],packet[TCP_seqnum+1], \
   packet[TCP_seqnum+2],packet[TCP_seqnum+3]);
   client_seqnum = client_seqnum + tcpdatalen_in;
   set_packet32(TCP_acknum,client_seqnum);
}
//******************************************************************
//*	Send TCP Packet
//*   This routine assembles and sends a complete TCP/IP packet.
//*   40 bytes of IP and TCP header data is assumed.
//******************************************************************
void send_tcp_packet()
{
   //count IP and TCP header bytes.. Total = 40 bytes
   ip_packet_len = 40 + tcpdatalen_out;
   packet[ip_pktlen] = make8(ip_packet_len,1);
   packet[ip_pktlen+1] = make8(ip_packet_len,0);
   setipaddrs();

   data_L = packet[TCP_srcport];
   packet[TCP_srcport] = packet[TCP_destport];
   packet[TCP_destport] = data_L;
   data_L = packet[TCP_srcport+1];
   packet[TCP_srcport+1] = packet[TCP_destport+1];
   packet[TCP_destport+1] = data_L;

   assemble_ack();
   set_packet32(TCP_seqnum,my_seqnum);


   packet[TCP_hdrflags+1] = 0x00;
   ACK_OUT;
   if(flags & finflag)
   {
      FIN_OUT;
      clr_finflag;
   }

   packet[TCP_cksum] = 0x00;
   packet[TCP_cksum+1] = 0x00;

   hdr_chksum =0;
   hdrlen = 0x08;
   addr = &packet[ip_srcaddr];
   cksum();
   hdr_chksum = hdr_chksum + packet[ip_proto];
   tcplen = ip_packet_len - ((packet[ip_vers_len] & 0x0F) * 4);
   hdr_chksum = hdr_chksum + tcplen;
   hdrlen = tcplen;
   addr = &packet[TCP_srcport];
   cksum();
   chksum16= ~(hdr_chksum + ((hdr_chksum & 0xFFFF0000) >> 16));
   packet[TCP_cksum] = make8(chksum16,1);
   packet[TCP_cksum+1] = make8(chksum16,0);

   txlen = ip_packet_len + 14;
   if(txlen < 60)
      txlen = 60;
   data_L = make8(txlen,0);
   data_H = make8(txlen,1);
   write_rtl(CR,0x22);
   write_rtl(TPSR,txstart);
   write_rtl(RSAR0,0x00);
   write_rtl(RSAR1,0x40);
   write_rtl(ISR,0xFF);
   write_rtl(RBCR0,data_L);
   write_rtl(RBCR1,data_H);
   write_rtl(CR,0x12);

   for(i=0;i<txlen;++i)
      write_rtl(RDMAPORT,packet[enetpacketDest0+i]);

   byte_read = 0;
   while(!(byte_read & RDC))
      read_rtl(ISR);

   write_rtl(TBCR0,data_L);
   write_rtl(TBCR1,data_H);
   write_rtl(CR,0x24);
}
//******************************************************************
//*	Read/Write for show_regs
//*   This routine reads a NIC register and dumps it out to the
//*   serial port as ASCII.
//******************************************************************
void readwrite()
{
     read_rtl(i);
     bin2hex(byte_read);
     printf("\t%c%c",high_char,low_char);
}
//******************************************************************
//*	Displays Control Registers in Pages 1, 2 and 3
//*   This routine dumps all of the NIC internal registers
//*   to the serial port as ASCII characters.
//******************************************************************
void show_regs()
{
   write_rtl(CR,0x21);
   cls();
   printf("\r\n");
   printf("    Realtek 8019AS Register Dump\n\n\r");
   printf("REG\tPage0\tPage1\tPage2\tPage3\n\r");

   for(i=0;i<16;++i)
   {
     bin2hex((unsigned char) i);
     printf("%c%c",high_char,low_char);
     write_rtl(CR,0x21);
     readwrite();
     write_rtl(CR,0x61);
     readwrite();
     write_rtl(CR,0xA1);
     readwrite();
     write_rtl(CR,0xE1);
     readwrite();
     printf("\r\n");
   }
}

/*!
    \brief print hexdump of a buffer as chars
    \param 1: [IN]  buffer, buffer to be hexdumped, observed
    \param 2: [IN]  len, length of buffer to be hexdumped
*/

void hexdump_( unsigned char *p, unsigned int len )
{
    if ( p == NULL || len < 0 )
    {
        return;
    }
    char out [ 128 ];
    unsigned char *line = p;
    int i, thisline, offset, ct = 0;
    offset = 0;

    while (offset < len)
    {
        snprintf(out + ct, 6, "%04X ", offset);
        ct += 5;
        if( ( len - offset ) > 16 )
        {
            thisline = 16;
        }
        else
        {
            thisline = (len - offset) % 16;
            if ( thisline == 0 ) thisline = 16;
        }

        for (i = 0; i < thisline; i++)
        {
            snprintf(out + ct, 4, "%02X ", line[i]);
            ct += 3;
        }

        if (thisline < 16)
        {
            for( i = thisline; i < 16; i++)
            {
                snprintf(out + ct, 4, "   ");
                ct += 3;
            }
        }

        for (i = 0; i < thisline; i++)
        {
            snprintf(out + ct, 2,
                     "%c", (line[i] >= 0x20 &&
                            line[i] < 0x7f)?
                            line[i] : '.');
            ct += 1;
        }
        *(out + ct) = '\0';
        ct = 0;
        printf("%s\r\n", out);
        offset += thisline;
        line += thisline;
    }
}

/*!
    \brief print hexdump of a buffer as chars
    \param 1: [IN]  buffer, buffer to be hexdumped, observed
    \param 2: [IN]  len, length of buffer to be hexdumped
    \note     Wrapper to hexdump_
*/
void hexdump( unsigned char *p, unsigned int len )
{
    printf("\r\n== hex %d chars ==\r\n", len);
    hexdump_( p, len );
    printf("== end hex ==\r\n");
}

//******************************************************************
//*	Dump Receive Ring Buffer Header
//*   This routine dumps the 4-byte receive buffer ring header
//*   to the serial port as ASCII characters.
//******************************************************************
void dump_header()
{
    for(i=0;i<4;++i)
      {
         bin2hex(pageheader[i]);
         printf("\r\n%c%c",high_char,low_char);
      }
}
//******************************************************************
//*	Converts Binary to Displayable Hex Characters
//*   ie.. 0x00 in gives 0x30 and 0x30 out
//******************************************************************
void bin2hex(unsigned char binchar)
{
   high_nibble = (binchar & 0xF0) / 16;
   if(high_nibble > 0x09)
      high_char = high_nibble + 0x37;
   else
      high_char = high_nibble + 0x30;

   low_nibble = (binchar & 0x0F);
   if(low_nibble > 0x09)
      low_char = low_nibble + 0x37;
   else
      low_char = low_nibble + 0x30;
}
//******************************************************************
//*	Used with Tera Term to clear the screen (VT-100 command)
//******************************************************************
void cls(void)
{
   printf("%c[2J",esc);
}
//******************************************************************
//*   show_packet
//*	This routine is for diagnostic purposes and displays
//*   the Packet Buffer memory in the AVR.
//******************************************************************
void show_packet()
{
   cls();
   printf("\r\n");
   data_L = 0x00;
   for(i=0;i<96;++i)
   {
      bin2hex(packet[i]);
      printf(" %c%c",high_char,low_char);
      if(++data_L == 0x10)
         {
            data_L = 0x00;
            printf("\r\n");
         }
   }
}
//******************************************************************
//*   show_aux_packet
//*	This routine is a diagnostic that displays Auxillary
//*   Packet Buffer buffer memory in the AVR.
//******************************************************************
void show_aux_packet()
{
   cls();
   printf("\r\n");
   data_L = 0x00;
   for(i=0;i<80;++i)
   {
      bin2hex(aux_data[i]);
      printf(" %c%c",high_char,low_char);
      if(++data_L == 0x10)
         {
            data_L = 0x00;
            printf("\r\n");
         }
   }
}
//******************************************************************
//*	Write to NIC Control Register
//******************************************************************
void write_rtl(unsigned int regaddr, unsigned int regdata)
{
    rtladdr = regaddr;
    rtldata = regdata;
    tortl;
	asm volatile("nop\n\t"::);
    clr_iow_pin;
	asm volatile("nop\n\t"::);
    set_iow_pin;
	asm volatile("nop\n\t"::);
    fromrtl;
	PORTA = 0xFF; 
}
//******************************************************************
//*	Read From NIC Control Register
//******************************************************************
void read_rtl(unsigned int regaddr)
{
   fromrtl;
   PORTA = 0xFF; 
   rtladdr = regaddr;
   clr_ior_pin;
   asm volatile("nop\n\t"::);
   asm volatile("nop\n\t"::);
   byte_read = PINA;
   asm volatile("nop\n\t"::);
   set_ior_pin;
}
//******************************************************************
//*	Handle Receive Ring Buffer Overrun
//*   No packets are recovered
//******************************************************************
void overrun(void)
{
   read_rtl(CR);
   data_L = byte_read;
   write_rtl(CR,0x21);
   _delay_ms(2);
   write_rtl(RBCR0,0x00);
   write_rtl(RBCR1,0x00);
   if(!(data_L & 0x04))
      resend = 0;
   else if(data_L & 0x04)
      {
         read_rtl(ISR);
         data_L = byte_read;
         if((data_L & 0x02) || (data_L & 0x08))
            resend = 0;
         else
            resend = 1;
      }

   write_rtl(TCR,0x02);
   write_rtl(CR,0x22);
   write_rtl(BNRY,rxstart);
   write_rtl(CR,0x62);
   write_rtl(CURR,rxstart);
   write_rtl(CR,0x22);
   write_rtl(ISR,0x10);
   write_rtl(TCR,tcrval);
}
//******************************************************************
//*	Echo Packet Function
//*   This routine does not modify the incoming packet size and
//*   thus echoes the original packet structure.
//******************************************************************
void echo_packet()
{
   write_rtl(CR,0x22);
   write_rtl(TPSR,txstart);
   write_rtl(RSAR0,0x00);
   write_rtl(RSAR1,0x40);
   write_rtl(ISR,0xFF);
   write_rtl(RBCR0,pageheader[enetpacketLenL] - 4 );
   write_rtl(RBCR1,pageheader[enetpacketLenH]);
   write_rtl(CR,0x12);

   txlen = make16(pageheader[enetpacketLenH],pageheader[enetpacketLenL]) - 4;
   for(i=0;i<txlen;++i)
      write_rtl(RDMAPORT,packet[enetpacketDest0+i]);

   byte_read = 0;
   while(!(byte_read & RDC))
      read_rtl(ISR);

   write_rtl(TBCR0,pageheader[enetpacketLenL] - 4);
   write_rtl(TBCR1,pageheader[enetpacketLenH]);
   write_rtl(CR,0x24);
   
}
//******************************************************************
//*	Get A Packet From the Ring
//*   This routine removes a data packet from the receive buffer
//*   ring.
//******************************************************************
void get_frame()
{
   //execute Send Packet command to retrieve the packet
   write_rtl(CR,0x1A);
   for(i=0;i<4;++i)
      {
         read_rtl(RDMAPORT);
         pageheader[i] = byte_read;
      }
   rxlen = make16(pageheader[enetpacketLenH],pageheader[enetpacketLenL]);
   printf( "Len [%d]", rxlen );
   for(i=0; i < rxlen;++i)
      {
         read_rtl(RDMAPORT);
         //dump any bytes that will overrun the receive buffer
         if(i < 96)
            packet[i] = byte_read;
      }

   printf( "pageheader");
   hexdump( pageheader, 4 );
   printf( "packet");
   hexdump( packet, 96 );
   
   while(!(byte_read & RDC))
   {
      read_rtl(ISR);
      printf( "%X ", byte_read );
   }
   write_rtl(ISR,0xFF);
   printf( "\r\nprocessing ARP packet type0 [%X]"
           " type1 [%X]\r\n", packet[enetpacketType0],
            packet[enetpacketType1] );
   //process an ARP packet
   if(packet[enetpacketType0] == 0x08 && packet[enetpacketType1] == 0x06)
   {
      if(packet[arp_hwtype+1] == 0x01 &&
      packet[arp_prtype] == 0x08 && packet[arp_prtype+1] == 0x00 &&
      packet[arp_hwlen] == 0x06 && packet[arp_prlen] == 0x04 &&
      packet[arp_op+1] == 0x01 &&
      MYIP[0] == packet[arp_tipaddr] &&
      MYIP[1] == packet[arp_tipaddr+1] &&
      MYIP[2] == packet[arp_tipaddr+2] &&
      MYIP[3] == packet[arp_tipaddr+3] )
	  arp();
   }
   //process an IP packet
   else if(packet[enetpacketType0] == 0x08 && packet[enetpacketType1] == 0x00)
   {
      printf( "packet [%u.%u.%u.%u] myip [%u.%u.%u.%u]\r\n",
               packet[ip_destaddr], packet[ip_destaddr+1],
               packet[ip_destaddr+2], packet[ip_destaddr+3],
               MYIP[0], MYIP[1], MYIP[2], MYIP[3] );
      if( packet[ip_destaddr] == MYIP[0]
          && packet[ip_destaddr+1] == MYIP[1]
          && packet[ip_destaddr+2] == MYIP[2]
          && packet[ip_destaddr+3] == MYIP[3] )
      {
          if(packet[ip_proto] == PROT_ICMP)
             icmp();
          else if(packet[ip_proto] == PROT_UDP)
             udp();
          else if(packet[ip_proto] == PROT_TCP)
             tcp();
      }
   }
}
//******************************************************************
//*	SETIPADDRS
//*   This function builds the IP header.
//******************************************************************
void setipaddrs()
{
   //move IP source address to destination address
   packet[ip_destaddr]=packet[ip_srcaddr];
   packet[ip_destaddr+1]=packet[ip_srcaddr+1];
   packet[ip_destaddr+2]=packet[ip_srcaddr+2];
   packet[ip_destaddr+3]=packet[ip_srcaddr+3];
   //make ethernet module IP address source address
   packet[ip_srcaddr]=MYIP[0];
   packet[ip_srcaddr+1]=MYIP[1];
   packet[ip_srcaddr+2]=MYIP[2];
   packet[ip_srcaddr+3]=MYIP[3];
   //move hardware source address to destinatin address
   packet[enetpacketDest0]=packet[enetpacketSrc0];
   packet[enetpacketDest1]=packet[enetpacketSrc1];
   packet[enetpacketDest2]=packet[enetpacketSrc2];
   packet[enetpacketDest3]=packet[enetpacketSrc3];
   packet[enetpacketDest4]=packet[enetpacketSrc4];
   packet[enetpacketDest5]=packet[enetpacketSrc5];
   //make ethernet module mac address the source address
   packet[enetpacketSrc0]=MYMAC[0];
   packet[enetpacketSrc1]=MYMAC[1];
   packet[enetpacketSrc2]=MYMAC[2];
   packet[enetpacketSrc3]=MYMAC[3];
   packet[enetpacketSrc4]=MYMAC[4];
   packet[enetpacketSrc5]=MYMAC[5];

   //calculate the IP header checksum
   packet[ip_hdr_cksum]=0x00;
   packet[ip_hdr_cksum+1]=0x00;

   hdr_chksum =0;
   hdrlen = (packet[ip_vers_len] & 0x0F) * 4;
   addr = &packet[ip_vers_len];
   cksum();
   chksum16= ~(hdr_chksum + ((hdr_chksum & 0xFFFF0000) >> 16));
   packet[ip_hdr_cksum] = make8(chksum16,1);
   packet[ip_hdr_cksum+1] = make8(chksum16,0);
 }
//******************************************************************
//*	CHECKSUM CALCULATION ROUTINE
//******************************************************************
void cksum()
{
      while(hdrlen > 1)
      {
         data_H=*addr++;
         data_L=*addr++;
         chksum16=make16(data_H,data_L);
         hdr_chksum = hdr_chksum + chksum16;
         hdrlen -=2;
      }
      if(hdrlen > 0)
      {
         data_H=*addr;
         data_L=0x00;
         chksum16=make16(data_H,data_L);
         hdr_chksum = hdr_chksum + chksum16;
      }
}
//******************************************************************
//*	Initialize the RTL8019AS
//******************************************************************
void init_RTL8019AS(void)
{
   fromrtl;                           // PORTA data lines = input
   PORTA = 0xFF; 
   DDRB = 0xFF;
   rtladdr = 0x00;                    // clear address lines
   DDRC = 0xFF;
   DDRD = 0xFA;		 				   // setup IOW, IOR, EEPROM,RXD,TXD,CTS,LE						
   PORTD = 0x05;					   // enable pullups on input pins

   //clr_le_pin;						   //initialize latch enable for HCT573
   clr_EEDO;
   set_iow_pin;                   	   // disable IOW
   set_ior_pin;                   	   // disable IOR
   set_rst_pin;                   	   // put NIC in reset
   _delay_ms(4);                        // delay at least 1.6ms
   clr_rst_pin;						   // disable reset line
 
   read_rtl(RSTPORT);                 // read contents of reset port
   write_rtl(RSTPORT,byte_read);      // do soft reset
   _delay_ms(10);                       // give it time
   read_rtl(ISR);                     // check for good soft reset
   if(!(byte_read & RST))
   {
    while(1){
    printf("RTL8019AS INIT FAILED!\r\n");
	_delay_ms(1000);
	}
   }
   write_rtl(CR,0x21);       // stop the NIC, abort DMA, page 0
   _delay_ms(4);               // make sure nothing is coming in or going out
   write_rtl(DCR,dcrval);    // 0x58
   write_rtl(RBCR0,0x00);
   write_rtl(RBCR1,0x00);
   write_rtl(RCR,0x04);
   write_rtl(TPSR,txstart);
   write_rtl(TCR,0x02);
   write_rtl(PSTART,rxstart);
   write_rtl(BNRY,rxstart);
   write_rtl(PSTOP,rxstop);
   write_rtl(CR,0x61);
   write_rtl(CURR,rxstart);
   for(i=0;i<6;++i)
      write_rtl(PAR0+i, MYMAC[i]);

   write_rtl(CR,0x22);
   write_rtl(ISR,0xFF);
   write_rtl(IMR,imrval);
   write_rtl(TCR,tcrval);
}
//******************************************************************
//*	MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN
//******************************************************************
int main(void)
{
   init_USART();
   init_RTL8019AS();
   show_regs();
   clr_synflag;
   clr_finflag;
   printf("YesHog\r\n");
//******************************************************************
//*	Look for a packet in the receive buffer ring
//******************************************************************
   while(1)
   {
      //start the NIC
      write_rtl(CR,0x22);
      printf( "Wrote CR [22] PIND [%x] "
                   "INT0_pin [%x]\r\n",
                      PIND, INT0_pin );
      //wait for a good packet
      while(!(PIND & INT0_pin));
      
      //read the interrupt status register
      printf( "PIND [%X] ISR [%X] byte[%X]"
              "\r\n", PIND, ISR, byte_read );
      read_rtl(ISR);

      printf( "PIND [%X] ISR [%X] byte[%X] OVW [%X]"
              "\r\n", PIND,  ISR, byte_read, OVW );
      //if the receive buffer has been overrun
      if(byte_read & OVW)
         overrun();

      printf( "PIND [%X] ISR [%X] byte[%X] PRX[%X]"
              "\r\n", PIND, ISR, byte_read, PRX );
      //if the receive buffer holds a good packet
      if(byte_read & PRX)
         get_frame();


      //if BNRY = CURR, the buffer is empty
         read_rtl(BNRY);
         data_L = byte_read;
         write_rtl(CR,0x62);
         read_rtl(CURR);
         data_H = byte_read;
         write_rtl(CR,0x22);
      //buffer is not empty.. get next packet
         if(data_L != data_H)
            get_frame();

      //reset the interrupt bits
      write_rtl(ISR,0xFF);
   }
}
