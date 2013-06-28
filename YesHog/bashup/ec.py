def ec_pt_dbl_get_s( a, x, y, p ):
    n = (3*x*x) + a
    d = Integer( (2*y) )
    i = d.inverse_mod( p )
    s = mod( n*i, p )
    return s

def ec_pt_add_get_s( x, y, x1, y1, p ):
    h = Integer( (x - x1) )
    c = h.inverse_mod( p )
    s = mod( (y - y1) * c, p )
    return s

def ec_pt_add( x, y, x1, y1, p ):
    s = ec_pt_add_get_s( x, y, x1, y1, p )
    ssq = s*s
    xr = mod((ssq - x - x1), p)
    yr = mod( (-1*y + s*(x-xr)), p )
    return (xr,yr)


def ec_pt_dbl( a, x, y, p ):
    s = ec_pt_dbl_get_s( a, x, y, p )
    ssq = s*s
    xr = mod((ssq - 2*x), p)
    yr = mod( (-1*y + s*(x-xr)), p )
    return (xr, yr)

def ec_scalar_mul(u, a, xx, yy, p):
    x = xx
    y = yy
    i = 0
    for bit in bin(u)[3:]:
        (x, y) = ec_pt_dbl( a, x, y, p )
        print 'Iteration', i
        print 'X=[', Integer(x).str(base=16).upper(), \
              '], Y=[', Integer(y).str(base=16).upper(), ']'
        #print (x, y)
        if bit == '1':
            (x, y) = ec_pt_add( x, y, xx, yy, p )
            print 'X=[', Integer(x).str(base=16).upper(), \
                  '], Y=[', Integer(y).str(base=16).upper(), ']'
            #print (x,y)
        i = i + 1
    return x

def ec_test_secp160r1():
    return ec_scalar_mul(0xCF6EE5683057F7BA45E61E6F2848DAE8406F15C8,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC,0x4A96B5688EF573284664698968C38BB913CBFC82,0x23A628553168947D59DCC912042351377AC5FB32,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF)

def ec_test_ecdh_client():
    return ec_scalar_mul(0x83F43D503FA22FE94341BD17C371A44F9CD2356C2108CC556C6C7D5C6B3A68C5,0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,0x83B4A60A58CFB94B4B3608B4DA6C53DFF546EB245C62797709848F69EE41B847,0xEF16D29B7147117703581B22F52E8943B2A6D74AF2B92EC93FC1E0EC1A2E06AF,0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)

def ec_test_ecdh_server():
    return ec_scalar_mul(0xCF9F5A0351B01AA5F053C8A7D0E3CE8605A67F60B5BD92A5D71341DFD63E9531,0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,0x685B4F6507FD80DD4FE2A9C32D7C0AB2D85FEC4F7740B44A6D9C75F86B93A517,0x897331FB0B30B2525B33FC5577EA3EFF66276C3370ABFC3A3823B3BC58136530,0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)

#ec_test_ecdh_client()
ec_test_ecdh_server()
