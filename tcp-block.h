#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <algorithm>
#include "networks.h"

#define ETH_LEN 14
#define TCP 6
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define MAC_LEN 17

#define FIN 1
#define RST 4
#define ACK 16

using std::cout;
using std::endl;
using std::search;
using std::string;

void usage()
{
    puts("syntax : tcp-block <interface> <pattern>\nsample : sudo tcp-block wlan0 \"Host: test.gilgil.net\"");
}

Mac getMac(char* dev)
{
    char buf[MAC_LEN + 1] = {0};

    int len = strlen(dev);
    int sz = len + 24; //NULL considered
    char *path = (char *)malloc(sz);
    if (path == NULL)
    {
        perror("path malloc failed");
        exit(-1);
    }

    snprintf(path, sz, "%s%s%s", "/sys/class/net/", dev, "/address");
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("open failed");
        exit(-1);
    }

    int bytes = read(fd, buf, MAC_LEN);
    if (bytes != MAC_LEN)
    {
        fprintf(stderr, "mac addr read failed");
        free(path);
        close(fd);
        exit(-1);
    }

    free(path);
    close(fd);
    return Mac(buf);
}

uint16_t calc_checksum()
{

}

void chkAndBlock(pcap_t* handle,char* dev,const u_char* packet,char* pat)
{
    PEthHdr ethHdr = (PEthHdr)packet;
    if(ethHdr->type()!=EthHdr::Ip4) return;

    PIpHdr ipHdr = (PIpHdr)(packet+ETH_LEN);
    if(ipHdr->protocol!=TCP) return;
    
    uint16_t iphdr_len = ((ipHdr->h_v)&0xf)<<2;

    PTcpHdr tcpHdr = (PTcpHdr)((u_char*)ipHdr+iphdr_len);
    uint16_t dport = tcpHdr->dport();
    bool mode;
    if(dport!=HTTP_PORT && dport!=HTTPS_PORT) return;
    else if(dport == HTTP_PORT) mode = true;
    else mode = false;

    uint16_t t_len = ipHdr->tlen();
    uint16_t tcphdr_len = (tcpHdr->offset)<<2;

    uint32_t pay_len = t_len - (tcphdr_len+iphdr_len);
    if(pay_len == 0) return; //check payload exists

    string payload = string((char*)((u_char*)tcpHdr+tcphdr_len),pay_len);
    string target = string(pat,strlen(pat));

    auto it = search(payload.begin(),payload.end(),std::boyer_moore_searcher(target.begin(),target.end()));
    if(it == payload.end()) return;  //not found 

    Mac myMac = getMac(dev);
    Block_pkt_1 pkt1;    //backward
    Block_pkt_2 pkt2;    //forward

    pkt1.ethHdr = pkt2.ethHdr = *ethHdr;
    pkt1.ipHdr = pkt2.ipHdr = *ipHdr;
    pkt1.tcpHdr = pkt2.tcpHdr = *tcpHdr;
        
    pkt1.ethHdr.smac_ = pkt2.ethHdr.smac_ = myMac;

    pkt1.ipHdr.dst = ipHdr->src;
    pkt1.ipHdr.src = ipHdr->dst;
    pkt1.ipHdr.ttl = pkt2.ipHdr.ttl = 0x80;  //ttl 1byte

    uint16_t tmp = sizeof(struct IpHdr) + sizeof(struct TcpHdr);
    if(mode) pkt1.ipHdr.t_len = htons(tmp + 58);
    else pkt1.ipHdr.t_len = htons(tmp);
    pkt2.ipHdr.t_len = htons(tmp);

    pkt1.tcpHdr.dst_port = tcpHdr->src_port;
    pkt1.tcpHdr.src_port = tcpHdr->dst_port;

    pkt2.tcpHdr.flags = (RST|ACK);
    if(mode) pkt1.tcpHdr.flags = (FIN|ACK);
    else pkt1.tcpHdr.flags = (RST|ACK);

    pkt1.tcpHdr.seq = tcpHdr->ack;
    pkt1.tcpHdr.ack = pkt2.tcpHdr.seq = htonl(ntohl(tcpHdr->seq)+pay_len);

    pkt1.ipHdr.checksum = 0xffff;
    pkt2.ipHdr.checksum = 0xffff;
    pkt1.tcpHdr.checksum = 0xffff;
    pkt2.tcpHdr.checksum = 0xffff;
    
    if(mode) pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt1), sizeof(pkt1));
    else pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt1), sizeof(pkt2));
    pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt2), sizeof(pkt2));
    puts("send!!!");
}

int watch(char* dev, char* pat)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n",dev,errbuf);
        return -1;
    }
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }
        chkAndBlock(handle,dev,packet,pat);
    }

    pcap_close(handle);
    return 0;
}