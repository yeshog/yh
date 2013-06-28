/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/
#include <common.h>

/* memfind.c mem related functions */
typedef struct _data_offsets
{
    SHORT len_upto;
    SHORT len_after;
    SHORT len_matched;
} data_offsets_st, *data_offsets;

/*!
  \brief Search for binary data of arbitrary length in a
         buffer
  \param:1 [IN] binary data buffer - haystack
  \param:2 [IN] length of buf in param 1
  \param:3 [IN] binary data buffer - needle
  \param:4 [IN] length of buf in param 3
  \return MEMFIND_NULL_INPUT if failure. Position of
          data found on success
  \TODO: Now buffers can only be 0x7FFF = 32k in len max
        since we blew up one bit. But thats fine since we
        dont handle too big buffers anyways
*/
SSHORT memfind( BYTE* haystack, SHORT hlen,
                BYTE* needle,   SHORT nlen )
{
    if( nlen > hlen
        || !haystack || !needle
        || hlen == 0 || nlen == 0 )
    {
        return -1;
    }
    int i, j, k;
    j = -1;
    k = hlen - nlen;
    for( i=0; (i <= k) &&
              ( j = memcmp( (const void*) (haystack + i),
                            (const void*)         needle,
                                   nlen )         != 0 );
        i++ );
    return (!j)? i : -1;
}

/*!
  \brief Calculate positions of data in buffer
         how much comes before and after it.
  \param:1 [IN] buffer to be searched
  \param:2 [IN] len of buffer in param 1
  \param:3 [IN] begining of string or buf to be replaced
                (from)
  \param:4 [IN] len of param 3
  \param:5 [IN] end of string or buf to be replaced
                (to )
  \param:6 [IN] length of param 5
  \param:7 [OUT] pointer to  data_offsets
  \return NULL if not found ptr to data_offsets 
          (populated param 5)
         if success
  \note ex. mem_calc_offsets( "abcdefg", 7, "bc", 2,
                                          "e",1, p )
            then after function executes:
                     p->len_upto = 1,
                     p->len_after = 2,
                     p->len_matched = 4
        buffers  > 65K are banned from this world.
        if param 5 is NULL only calculations for param 3
        are done
        ex. mem_calc_offsets( "abcdefg", 7, "bc", 2,
                                        NULL, 0, p )
            then after function executes:
                     p->len_upto = 1,
                     p->len_after = 4,
                     p->len_matched = 2
*/
data_offsets mem_calc_offsets(   BYTE* b,
                               SHORT l_b,
                                 BYTE* f,
                               SHORT l_f,
                                 BYTE* t,
                               SHORT l_t,
                         data_offsets o )
{
    /* sanity or lack thereof */
    if( !b || l_b <= 0 || !f || l_f <= 0 || !o )
        return NULL;

    SSHORT x = memfind( b, l_b, f, l_f );
    if ( x < 0 || x > l_b )
        return NULL;

    if( !t )
    {
        o->len_upto = x;
        o->len_after = (l_b - (x + l_f) );
        o->len_matched = l_f;
        return o;
    }
    SSHORT y   =  memfind( (b + x + l_f),
                      (l_b - (x + l_f) ),
                                t, l_t );
    if( y < 0 || y > (l_b - (x + l_f) ) )
    {
        return NULL;
    }
    SHORT k = ( l_f + y + l_t );
    o->len_upto = x;
    o->len_after = ( l_b - ( x + k ) );
    o->len_matched = k;
    return o;
}

/*!
  \brief Replace data in memory
  \param:1 [INOUT] buffer to be searched and modified (haystack)
  \param:2 [IN] size of buf (haystack) allocated in param 1
                MUST be > param 3
  \param:3 [IN] len of data in param 1
  \param:4 [IN] buf beginning to be searched start (needle start)
  \param:5 [IN] len of param 4
  \param:6 [IN] end of string or buf to be replaced (needle end )
  \param:7 [IN] length of param 6
  \param:8 [IN] replacement buf/string ( repl )
  \param:9 [IN] len of param 8
  \return New length of haystack (param 1). -1 on failure
  \note   Assumes haystack is of sufficient length to move/insert
          data w/o reallocing. i.e. caller makes sure param 3 and
          param 2 are correct and param 3 >= param 2
          ex.
              val = mem_replace( "abcdefg", 7, 8,
                                      "bc", 2,
                                       "f", 1,
                                     "123", 3 );
              then after execution:
                  param 1 = a123g
                  return val 5
              if param 8 is NULL then:
                  param 1 = ag
                  return val = 2
              if param 6 is NULL then:
                  param 1 = a123defg
                  return val = 8
*/
SWORD mem_replace( BYTE* b,  SHORT m_b,
                             SHORT l_b,
                   BYTE* f,  SHORT l_f,
                   BYTE* t,  SHORT l_t,
                   BYTE* r,  SHORT l_r )
{

    if( !b || l_b <= 0  || m_b <= 0
           || m_b < l_b || !f || l_f <=0 )
    {
        return MEMFIND_NULL_INPUT;
    }

    if( !r )
        l_r = 0;

    /* look for the data */
    data_offsets_st d_o, *d;
    d = mem_calc_offsets( b, l_b, f, l_f,
                          t, l_t, &d_o );
    if( d == NULL )
    {
        return MEMFIND_OFFSET_CALC_ERR;
    }

    SHORT new_l = d->len_upto + l_r +
                           d->len_after;
    if( new_l > m_b )
    {
        /*
         * Insufficient memory bail out
         * caller may use new_l
         */
        return
        MEMFIND_INSUFFICIENT_BUF_SZ|new_l;
    }
    /*
     *determine if at all we need to move data
     */
    SSHORT m_dir = (d->len_matched - l_r);

    if( m_dir != 0 )
    {
        memmove( b + (d->len_upto + l_r),
                 b +       (d->len_upto +
                         d->len_matched),
                          d->len_after );
    }
    if ( r )
    {
        memcpy( b + d->len_upto, r, l_r );
    }
    memset(b +       (d->len_upto + l_r) +
           d->len_after, 0, m_b - new_l );
    return new_l;
}

/*!
  \brief Replace data in memory
  \param:1 [INOUT] buffer to be searched and modified (haystack)
  \param:2 [IN] size of buf (haystack) allocated in param 1
                MUST be > param 3
  \param:3 [IN] len of data in param 1
  \param:4 [IN] buf beginning to be searched start (needle start)
  \param:5 [IN] len of param 4
  \param:6 [IN] starting from param 4, the length to replace
  \param:7 [IN] replacement buf/string ( repl )
  \param:8 [IN] len of param 8
  \return New length of haystack (param 1). -1 on failure
  \note   Just like mem_replace but now we use length
          Ex. Find were the buffer contains "\0x03\0x03"
              and when found replace next 3 bytes with the
              replacement buffer
          ex.
              val = mem_replace( "abcdefg", 8, 7,
                                      "bc", 2, 3,
                                      "123", 3 );
              then after execution:
                  param 1 = a123efg
                  return val 7
              if param 7 is NULL then:
                  param 1 = aefg
                  return val = 4
*/
SWORD mem_replace_starting_with( BYTE* b,  SHORT m_b,
                                           SHORT l_b,
                                 BYTE* f,  SHORT l_f,
                                           SHORT m_f,
                                 BYTE* r,  SHORT l_r )
{
    SSHORT x = memfind( b, l_b, f, l_f );
    if( x < 0 )
        return MEMFIND_DATA_NOT_FOUND;
    return x + mem_replace( b + x , m_b - x, l_b - x,
                                    b + x  ,     m_f,
                                    NULL   ,       0,
                                    r      ,   l_r );
}

/*!
 * \brief: find length of http/sip data
 */
SWORD find_content_length( char* data, SHORT d_len )
{
    if( !data )
    {
        return MEMFIND_NULL_INPUT;
    }
    data_offsets_st d_o, *d;

    /* last header followed by empty line */
    char * s = "\r\n\r\n";
    d = mem_calc_offsets( (BYTE*) data, d_len,
                                    (BYTE*) s,
                           strlen(s), NULL, 0,
                                       &d_o );
    if ( !d )
        return MEMFIND_NULL_INPUT;
    return d->len_after;
}

/*!
 * \brief: modify content length of http data
 * \note
 */
SWORD modify_content_length( char* data, SHORT d_len )
{
    SWORD x = find_content_length( data, d_len );
    if( x < 0 )
    {
        return x;
    }

    char buf[255];
    memset(buf, 0 , sizeof(buf));
    snprintf( buf,       sizeof(buf), "%s %d%s",
                                   HDR_CONT_LEN,
                                   x, HTTP_NL );

    /* the func will return MEMFIND_NULL_INPUT on overflows */
    return replace_str(            data, d_len,
                                  HDR_CONT_LEN,
                                HTTP_NL, buf );
}

/*!
 * \brief: Replace all occurences of a string with provided
           replacement
 * \param:1 [INOUT] buffer to be modified
 * \param:2 [IN] Max size of buf that param1 has been
                 allocated
 * \param:3 [IN] Beginning of string to replace
 * \param:4 [IN] End of string to replace
 * \param:5 [IN] Replacement string
 * \return Length of param1 after execution. -1 on failure.
 * \note wrapper around mem_replace.
 *       ex. replace_str( "12a12a", 10, "1","a", "34b")
 *           will return 34b34b in param 1
 *         If end is NULL or empty
 *                only param 3 will be replaced
 *         If replace with is NULL or empty
 *                param 3 will be deleted
 * \see mem_replace
 * \warning param1 has been allocated sufficient room as
 *          specified by param 2 ie. by caller.
 */

SWORD replace_str( char* buf, SHORT max_len,
                 char* attr, char* upto, char* repl )
{
    if( !buf || max_len < strlen( buf ) || !attr )
    {
        return MEMFIND_NULL_INPUT;
    }
    SWORD new_l = 0, pos= 0, d=0, t_l=0, l_b=0, l_e=0, l_r=0;
    t_l = strlen( buf );
    BYTE* tb = (BYTE*) buf;
    char *b, *e, *r;
    b = (attr)? ( (strlen(attr) > 0 ) ? attr:NULL ) : NULL;
    e = (upto)? ( (strlen(upto) > 0 ) ? upto:NULL ) : NULL;
    r = (repl)? ( (strlen(repl) > 0 ) ? repl:NULL ) : NULL;
    l_b = (b)? strlen(b) : 0;
    l_e = (e)? strlen(e) : 0;
    l_r = (r)? strlen(r) : 0;
    do
    {
        d = strlen( (char*) buf );
        pos = memfind( (BYTE*) buf,     strlen(buf),
                       (BYTE*) attr, strlen(attr) );
        if ( pos < 0 )
            break;
        new_l = mem_replace(  (BYTE*) buf, 
                           max_len - ((BYTE*) buf - tb),
                                 strlen(buf),
                              (BYTE*) b, l_b,
                              (BYTE*) e, l_e,
                              (BYTE*) r, l_r);
        buf += (pos + l_r);
        t_l += (new_l - d);
    } while ( new_l >= 0 );
    return t_l;
}
