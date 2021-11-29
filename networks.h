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
    char msg[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
}Block_pkt_1;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
}Block_pkt_2;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct
{
    Ip src;
    Ip dst;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t len;
}Pseudo_hdr;
#pragma pack(pop)