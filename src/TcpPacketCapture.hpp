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

typedef int (*ON_PACKET_LISTENER) (int len, const u_char*) ;

class TcpPacketCapture {
private:
    u_int listenIp = 0;
    char* devName = nullptr;
    char filterExp[32];
    pcap_t* deviceHandle;
    bool startState = false;


public:
    TcpPacketCapture(char* devName, uint32_t listenIp){
        this->devName = devName;
        this->listenIp = listenIp;


        unsigned char ipBytes[4];
        ipBytes[0] = listenIp & 0xFF;
        ipBytes[1] = (listenIp >> 8) & 0xFF;
        ipBytes[2] = (listenIp >> 16) & 0xFF;
        ipBytes[3] = (listenIp >> 24) & 0xFF;

        sprintf(filterExp, "%d.%d.%d.%d\n", ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]);
        char error[128];
        /* 打开设备 */
        if (!(deviceHandle = pcap_open_live(devName,   // 设备名
                                           65536,            // 要捕捉的数据包的部分
                                           true,             // 混杂模式
                                           1000,             // 读取超时时间
                                           error             // 错误缓冲池
            )))
            fprintf(stderr, "Couldn't open device %s: %s\n", "en0", error);
        printf("INIT SUCCESSFUL");
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
