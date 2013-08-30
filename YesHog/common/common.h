/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

/*
    \brief: With AVR we do some extra includes
            and skip file operations that are
            mainly for testing
*/
#include "types.h"
#include "error.h"
#include "sys_limits.h"
#ifdef _AVR_

#include <inttypes.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <util/atomic.h>
#include <util/delay.h>
#define _NEWLINE_ "\r\n"
#else
#define _NEWLINE_ "\n"
#endif

#define BUF_128_BYTES   128
#define BUF_256_BYTES   256
#define BUF_512_BYTES   512
#define BUF_1K_BYTES   1024
#define BUF_2K_BYTES   2048
#define BUF_4K_BYTES   4096
#define MIN_PKT_LEN      60
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define DIFF( a, b ) (((a) > (b)) ? ( a - b ):( b - a )
#define IS_OK (_res_ == 0 )
#define result_init(x) RESULT x = 0

#define xchg( t, x, y )                   \
          t _t_##t =   x;                 \
                 x  =   y;                \
                 y  =  _t_##t;

/* result, operation, on_fail_error_goto, stack of 2 errors
            _res_ = ( (g << SZ_SHORT) | (SHORT) _res_ );   */
#define op_chk( x, g )                                   \
        _res_ = x;                                       \
        if( _res_ != OK )                                \
            goto done

#define fillmem( b1, l1, b2, l2 )                                         \
         memcpy( (l1 > l2)? b1 + (l1 - l2) : b1, b2, (l2 > l1)? l1:l2 );  \
         if( l1 > l2 ) memset( b1, 0, (l1-l2) )

#define MEMFIND_INSUFFICIENT_BUF_SZ 0xFFFF0000
#define HDR_CONT_LEN "Content-Length:"
#define HTTP_NL      "\r\n\r\n"

SSHORT memfind( BYTE*, SHORT, BYTE*, SHORT);
SWORD mem_replace( BYTE*,   SHORT,   SHORT,
                            BYTE*,   SHORT,
                            BYTE*,   SHORT,
                            BYTE*,  SHORT);
SWORD mem_replace_starting_with(
                        BYTE*, SHORT, SHORT,
                        BYTE*, SHORT, SHORT,
                        BYTE*,  SHORT );
SWORD replace_str(   char*, SHORT,   char*,
                            char*,  char*);

/* log.c is common to AVR and x86 */
SHORT hexdump_(BYTE*, SHORT);
SHORT hexdump( BYTE*, SHORT);

#if defined(_X86_64_) || defined(_ARM_)
/* fileops.c , no file management in AVR */
BYTE* get_file_data(char*, SWORD*);
#define _NEWLINE_ "\n"
#endif
