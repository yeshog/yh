#include <net.h>

#define GET   "GET"
#define SPC   " "
#define HTTP  "HTTP"
#define SEP   "/"
#define VER   "1.1"
#define TL    "<"
#define TR    ">"
#define HTML  "html"
#define BODY  "body"
#define DEF   "Welcome to YesHog"
#define CRLF  "\r\n"
#define ROK   "HTTP/1.1 200 OK" CRLF

        /* "GET / HTTP/1.1" */
#define DEF_REQ GET SPC SEP SPC HTTP SEP VER

#define DEF_RSP          \
        ROK              \
        "Content-Length: 43" CRLF CRLF \
        TL HTML TR       \
          TL BODY TR     \
            DEF          \
          TL SEP BODY TR \
        TL SEP HTML TR

RESULT http_rx( yh_socket* );
RESULT http_process( BYTE**, SHORT, BYTE**, SHORT*, SHORT* );
