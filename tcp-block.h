#include <iostream>
#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <algorithm>
#include "networks.h"

#define ETH_LEN 14
#define TCP 6
#define HTTP_PORT 80
#define HTTPS_PORT 443

using std::cout;
using std::endl;
using std::search;
using std::string;

void usage()
{
    puts("syntax : tcp-block <interface> <pattern>\nsample : sudo tcp-block wlan0 \"Host: test.gilgil.net\"");
}

void chkAndBlock(pcap_t* handle,const u_char* packet,char* pat)
{
    PEthHdr ethhdr = (PEthHdr)packet;
    if(ethhdr->type()!=EthHdr::Ip4) return;

    PIpHdr iphdr = (PIpHdr)(packet+ETH_LEN);
    if(iphdr->protocol!=TCP) return;
    
    uint16_t iphdr_len = ((iphdr->h_v)&0xf)<<2;

    PTcpHdr tcpHdr = (PTcpHdr)((u_char*)iphdr+iphdr_len);
    uint16_t dport = tcpHdr->dport();
    
    if(dport!=HTTP_PORT && dport!=HTTPS_PORT) return;

    uint16_t t_len = iphdr->tlen();
    uint16_t tcphdr_len = (tcpHdr->offset)<<2;

    uint32_t pay_len = t_len - (tcphdr_len+iphdr_len);
    if(pay_len == 0) return; //check payload exists

    string payload = string((char*)((u_char*)tcpHdr+tcphdr_len),pay_len);
    string target = string(pat,strlen(pat));

    auto it = search(payload.begin(),payload.end(),std::boyer_moore_searcher(target.begin(),target.end()));
    if(it == payload.end()) return;  //not found 

    Mac srcMac = ethhdr->smac();
    Mac dstMac = ethhdr->dmac();
    Ip srcIp = iphdr->sip();
    Ip dstIp = iphdr->dip();
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
        chkAndBlock(handle,packet,pat);
    }

    pcap_close(handle);
    return 0;
}