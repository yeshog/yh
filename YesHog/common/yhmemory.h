/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include <common.h>
/* This is the maximum memory we can allocate */

void* yh_calloc( SHORT, size_t );
SHORT yh_free( void*, SHORT );
SSHORT yh_check_free( SHORT );
void* yh_realloc( void*, SHORT, SHORT );
SHORT yh_mem( void );
#ifdef _AVR_
#include <avr/pgmspace.h>
#define ONFLASH PROGMEM
#define yh_memcpy memcpy_PF
#define yh_memcmp memcmp_PF
#else
#define yh_memcpy memcpy
#define yh_memcmp memcmp
#define ONFLASH
#endif
