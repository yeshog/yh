#include "test_live.h"

#define SOCK_FAILED  -1
#define BIND_FAILED -2
#define LISTEN_FAILED -3
#define CONN_FAILED -4
#define CLOSE_FAILED -5
#define BUF_LEN_ZERO -6
#define CONN_WRITE_FAILED -7

RESULT no_resize( yh_socket* s, SHORT l )
{
    return OK;
}
RESULT test_handle_tls_rx( int conn, BYTE* buf, SHORT buflen )
{
    RESULT res;
    ssize_t r = read( conn, buf, buflen );
    if( r <= 0 )
    {
        printf( "Zero bytes read from buffer\n" );
        return BUF_LEN_ZERO;
    }
    yh_socket* s = tcp_get_sock(NULL);
    s->app = buf;
    printf( "Sock App [%p]\n", s->app );
    s->applen = r;
    s->resize_cb = no_resize;
    res = tls_rx( s );
    if( res != OK )
    {
        printf( "After test result [%X] Sock->App[%p]\n", res, s->app );
        return res;
    }
    printf( "After test Sock->App[%p]\n", s->app );
    r = write( conn, buf, s->txlen );
    if( r <= 0 )
    {
        printf( "Conn write failed \n" );
        return CONN_WRITE_FAILED;
    }
    return res;
}

int test_live(void)
{
    int ssock, conn, ret;
    struct    sockaddr_in servaddr;
    BYTE buf[1024];

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(__MYPORT);

    ssock = socket(AF_INET, SOCK_STREAM, 0);
    
    if ( ssock < 0 ) {
        printf( "socket failed\n");
        return SOCK_FAILED;
    }
    ret = bind(ssock, (struct sockaddr *) &servaddr, sizeof(servaddr));

    if ( ret < 0 )
    {
        printf("Bind Failed\n");
        return BIND_FAILED;
    }

    ret = listen( ssock, 1 );
    if ( ret < 0 )
    {
        printf("Listen Failed\n");
        return BIND_FAILED;
    }

    while ( 1 )
    {
        conn = accept( ssock, NULL, NULL );
        if( conn < 0 )
        {
            return CONN_FAILED;
        }
        do
        {
            ret = test_handle_tls_rx( conn, buf, sizeof(buf) );
            if( ret != OK )
            {
                printf( "tls returned err [%X]\n", ret );
                break;
            }
        } while ( 1 );
        ret = close( conn );
        if( ret < 0 )
        {
            printf( "Close failure\n" );
            return CLOSE_FAILED;
        }
        break;
    }

    return 0;
}

