/*
   Author: Yogesh Nagarkar
   Copyright: YesHog (www.yeshog.com)
*/

#include <yhmemory.h>

/*!
    \brief: With AVR we try to restrict mem allocs
            to an upper limit. With x86 we may have
            luxuries
*/
volatile SHORT _mem_avail_ = MEM_UPPER_LIMIT;
#ifdef _AVR_
/*!
    \brief: allocate n bytes of size s
    \note: wrapper around libc alloc to
           track memory limits.
*/
void* yh_calloc( SHORT n, size_t s )
{
    if( (s * n) > _mem_avail_ )
    {
        return NULL;
    }
    _mem_avail_ -= ( s * n );
    return calloc( n, s );
}

/*!
    \brief: re-allocate n bytes of size s
    \param1: memory ptr to be reallocated
    \param2: old memory size
    \param3: new memory size
    \note: wrapper around libc alloc to
           track memory limits.
*/
void* yh_realloc( void* b, SHORT o, SHORT n )
{
    /* no new memory needed */
    if( n < o ) return b;
    if( _mem_avail_ < (n - o) )
    {
        return NULL;
    }
    _mem_avail_ -= ( n - o );
    return realloc( b, n );
}

/*!
    \brief: check if r bytes can be allocated
    \note: param is short but return is SSHORT
           because we *never* allow MAX_SHORT
*/
SSHORT yh_check_free( SHORT r )
{
    SSHORT x = 0;
    /* future */
    ATOMIC_BLOCK( ATOMIC_RESTORESTATE )
    {
    /* end future */
    x = _mem_avail_ - r;
    /* future */
    }
    /* end future */
    return x;
}

/*!
    \brief: free s bytes of memory. p is
           of size s
    \note: wrapper aroung libc free that
          also tracks memory that is still
          available
*/
SHORT yh_free(void* p, SHORT s)
{
    //ATOMIC_BLOCK( ATOMIC_RESTORESTATE )
    //{
        _mem_avail_ += ( s );
    //}
    free( p );
    return _mem_avail_;
}

/*!
    \brief return avail memory
*/
SHORT yh_mem( void )
{
    return _mem_avail_;
}
#else
/*!
    \brief: allocate n bytes of size s
    \note: wrapper around libc alloc to
           track memory limits.
*/
void* yh_calloc( SHORT n, size_t s )
{
    _mem_avail_ -= ( s * n );
    return calloc( n, s );
}

/*!
    \brief: check if r bytes can be allocated
    \note: param is short but return is SSHORT
           because we *never* allow MAX_SHORT
*/
SSHORT yh_check_free( SHORT r )
{
    SSHORT x = 0;
    x = _mem_avail_ - r;
    return x;
}

/*!
    x86 return some number assuming
    this is test only and that we have
    infinite mem
*/
SHORT yh_mem( void )
{
    return _mem_avail_;
}
/*!
    caller (test.c) frees we dont do anything
*/
SHORT yh_free( void* p, SHORT l )
{
    _mem_avail_ += l;
    free( p );
    return _mem_avail_;
}
/*!
    \brief: re-allocate n bytes of size s
    \param1: memory ptr to be reallocated
    \param2: old memory size
    \param3: new memory size
    \note: wrapper around libc alloc to
           track memory limits.
*/
void* yh_realloc( void* b, SHORT o, SHORT n )
{
    /* no new memory needed */
    if( n < o ) return b;
    if( _mem_avail_ < (n - o) )
    {
        return NULL;
    }
    _mem_avail_ -= ( n - o );
    return realloc( b, n );
}
#endif
