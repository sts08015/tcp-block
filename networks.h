#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include <cstring>

#pragma pack(push, 1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
    char msg[58] = "\"HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n\"";
}HTTP_block_pkt;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
}HTTPS_block_pkt;
#pragma pack(pop)

