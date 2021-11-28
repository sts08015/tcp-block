#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "networks.h"

using std::cout;
using std::endl;

void usage()
{
    puts("syntax : tcp-block <interface> <pattern>\nsample : sudo tcp-block wlan0 \"Host: test.gilgil.net\"");
}

KINDS chk_kinds(struct pcap_pkthdr* header,const u_char* packet)
{
    //determine whether packet is http or https

}

void block(pcap_t* handle)
{
    //send forward,backward block packets
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
        KINDS kind = chk_kinds(header,packet);
        if(kind!=http && kind!=https) continue;
        else block(handle);
    }

    pcap_close(handle);
    return 0;
}