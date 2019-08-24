//
// Created by Deyu Heng on 2019-08-19.
//

#ifndef GTPV2_UTRANS_TCPPACKETCAPTURE_HPP
#define GTPV2_UTRANS_TCPPACKETCAPTURE_HPP


#include "pcap.h"
#include "math.h"
#include "packet.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "Util.hpp"


#pragma pack(1)


typedef struct __TCP_PACKET{
    u_char* SrcIP;
    u_char* DstIP;

    pk_big_uint16 SrcPort;
    pk_big_uint16 DstPort;


    ether_header* EtherHeader;
    PInernetProtocol InternetProtocol;
    PTCP TcpHeader;
    size_t TcpHeaderLen;

    u_char* TcpPayload;
    size_t TcpPayloadLen;
} TCP_PACKET, *PTCP_PACKET;

typedef int (*ON_PACKET_LISTENER) (PTCP_PACKET packet) ;


class TcpPacketCapture {
private:
    u_int listenIp = 0;
    char* devName = nullptr;
    char filterExp[128];
    pcap_t* deviceHandle;
    bool startState = false;
    struct bpf_program filter;

public:
    TcpPacketCapture(char* devName, char* listenIp){
        this->devName = devName;

        char error[128];

        if (!(deviceHandle = pcap_open_live(devName,         // 设备名
                                           65536,            // 要捕捉的数据包的部分
                                           true,             // 混杂模式
                                           1000,             // 读取超时时间
                                           error             // 错误缓冲池
            )))
            fprintf(stderr, "Couldn't open device %s: %s\n", "en0", error);
        sprintf(this->filterExp, "ip %s", listenIp);

        if (pcap_compile(deviceHandle, &filter, filterExp, 0, 0) == -1) {
            printf("Bad filter - %s\n", pcap_geterr(handle));
            return 2;
        }
    }

    void StartListen(ON_PACKET_LISTENER listener){
        if(startState) return;
        startState = true;

        struct pcap_pkthdr *header;

        const u_char* packet;

        int res;
        while((res = pcap_next_ex(deviceHandle, &header, &packet)) >= 0){
            if(!startState) break;
            if(res == 0) continue;

            auto eth_header = (struct ether_header *) packet;

            if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
                continue;
            }

            auto protocol = (PInernetProtocol)((uint64_t)packet + sizeof(ether_header));
            if(protocol->Protocol == IPPROTO_TCP){
                printf("TCP: ");
            }
            else{
                continue;
            }

            auto tcp = (PTCP)((uint64_t)protocol + sizeof(InernetProtocol));

            size_t tcpHeaderLength = tcp->HeaderLen << 2; // 2 ^ n
            auto tcpPayload = (u_char*)((uint64_t)tcp + tcpHeaderLength);

            size_t tcpPayloadLength = header->len - sizeof(ether_header) - sizeof(InernetProtocol) - tcpHeaderLength;

            Util::printMac(eth_header->ether_shost);
            printf(" -> ");
            Util::printMac(eth_header->ether_dhost);
            printf("\n");

            printf("Src: %s, ", inet_ntoa(*(in_addr*)&protocol->SrcIP));
            printf("Dst: %s", inet_ntoa(*(in_addr*)&protocol->DstIP));


            printf("\nSrcPort: %d, DestPort: %d, Seq: %d, WndSize: %d \n", ntohs(tcp->SrcPort), ntohs(tcp->DstPort), ntohl(tcp->SeqNum), ntohs(tcp->WndSize));

            printf("\n%d: ", header->len);
            Util::printHEX(packet, header->len);

            printf("\n|- Header\t(0x%08x) %ld: ", eth_header, sizeof(ether_header));
            Util::printHEX(eth_header, sizeof(ether_header));

            printf("\n|- Protocol\t(0x%08x) %ld: ", protocol, sizeof(InernetProtocol));
            Util::printHEX(protocol, sizeof(InernetProtocol));

            printf("\n|- TCP    \t(0x%08x) %d: ", tcp, tcpHeaderLength);
            Util::printHEX(tcp, tcpHeaderLength);

            printf("\n+- TCP Seg\t(0x%08x) %ld: ", tcpPayload, tcpPayloadLength);
            Util::printHEX(tcpPayload, tcpPayloadLength);

            printf("\n\n");

            TCP_PACKET tcpPacket{
                .DstPort = tcp->DstPort,
                .SrcPort = tcp->SrcPort,
                .DstIP = protocol->DstIP,
                .SrcIP = protocol->SrcIP,
                .EtherHeader = eth_header,
                .InternetProtocol = protocol,
                .TcpHeaderLen = tcpHeaderLength,
                .TcpHeader = tcp,
                .TcpPayload = tcpPayload,
                .TcpPayloadLen = tcpHeaderLength
            };

            listener(&tcpPacket);
        }
    }

    void StopListen(){
        startState = false;
        pcap_close(deviceHandle);
    }

    static pcap_if_t* GetDeviceList(){
        pcap_if_t* devicesList;
        char error[128];
        if (-1 == pcap_findalldevs(&devicesList, error))
        {
            throw error;
        }
        return devicesList;
    }

    static void FreeDeviceList(pcap_if_t* list){
        pcap_freealldevs(list);
    }


};


#endif //GTPV2_UTRANS_TCPPACKETCAPTURE_HPP
