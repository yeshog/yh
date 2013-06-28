/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include <yhmemory.h>
#include "l234.h"
extern BYTE __IP[4];

#define IP_HEADER_VER_HDRLEN_DS_OFFSET  0
#define IP_HEADER_DATA_LEN_OFFSET       2
#define IP_HEADER_ID_OFFSET             4
#define IP_HEADER_FLAGS_FRAG_OFFSET     6
#define IP_HEADER_TTL_OFFSET            8
#define IP_HEADER_PROTOCOL_OFFSET       9
#define IP_HEADER_CHECKSUM_OFFSET      10
#define IP_HEADER_SRC_IP_OFFSET        12
#define IP_HEADER_DST_IP_OFFSET        16
#define IP_HEADER_SZ_WORD               4

RESULT ip_process( ip_header_p, SHORT );

