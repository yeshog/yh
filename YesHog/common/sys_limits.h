#define      MEM_UPPER_LIMIT        3192
#define      MAX_PKT_SZ             1460
#define      MAX_RX_FRAME_LEN       0x71C
#define      MAX_IP_DATA_LEN        MAX_RX_FRAME_LEN - 20
#define      MAX_TCP_DATA_LEN       MAX_IP_DATA_LEN -  20
#define      MIN_TCP_HEADER_LEN     20
/* data + options */
#define      MAX_TCP_HEADER_LEN      50
#define      MAX_ERR_STACK            4
#define      MAX_EC_BITLEN          256
#define      MAX_TLS_APP_DATA       468
#define      MAX_TLS_RECS             5
#define      MAX_MBUF_SZ           1024
#define      MIN_FRAME_LEN           42
/* yh config MAX_OPAQUE_SEC_DATA_SZ */
/* this number is calculated from crypto 'test_sizes' test */
#define      MAX_OPAQUE_SEC_DATA_SZ 181
/* end yh config MAX_OPAQUE_SEC_DATA_SZ */
#define      MAX_MODINV_TMP_VAR_LEN MAX_EC_BITLEN
