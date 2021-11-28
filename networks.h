#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
}Block_pkt;
#pragma pack(pop)

