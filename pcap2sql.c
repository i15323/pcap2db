#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define MAX_HOST_COUNT 1000000
#define MAX_PACKET_COUNT 1000000000

/*===================================================
  Function Prototype
===================================================*/
int read_pcap();
char *generate_SQL();

/*===================================================
  STRUCT Definition
===================================================*/
struct tcpip_header_field
{
    // Config
    int isTCP; // TCP => 1, UDP => 0

    // Packet Information

    // Internet Protocol
    int 
    // Transmission Control Protocol

    // User Datagram Protocol

};

struct host_list
{
    char srcip[16];
    struct pcap_pkthdr pktlist[MAX_PACKET_COUNT];
};

/*===================================================
  Main Function
===================================================*/
int main()
{
    struct host_list a[MAX_HOST_COUNT];
    struct host_list *p;
    const unsigned char *pkt;
    char pcap_errorbuf[PCAP_ERRBUF_SIZE];   
    const char *pcap_path = "../dark.pcap";
    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(pcap_path,
                                                    PCAP_TSTAMP_PRECISION_NANO,
                                                    pcap_errorbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open %s\n", pcap_errorbuf);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr pkthdr;

    while ((pkt = pcap_next(pcap, &pkthdr)))
    {
        // ホスト存在判定
        for (int i = 0; i < MAX_HOST_COUNT; i++)
        {
            // 存在した場合
            //if (strcmp(.sip, a[i].pktlst.sip))
            //{
                                              
            //}
            // 存在しない場合
            //else
           // {
           //     
           // }
        }
    }

    return EXIT_SUCCESS;   
}

pcap_t *read_pcap(char *FileName)
{
    char pcap_errorbuf[PCAP_ERRBUF_SIZE];   
    struct pcap_pkthdr pkthdr;
    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(FileName,
                                                           PCAP_TSTAMP_PRECISION_NANO,
                                                           pcap_errorbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open %s \n", pcap errbuf);
        exit(EXIT_FAILURE);
    }
    
    while ((pkt = pcap_next(pcap, &pkthdr)))
    {


    }

    return pcap;
}

char *generate_SQL()
{
    return
}

int execute_SQL()
{

}

struct tcpip_header_field capture()
{

    return
}

