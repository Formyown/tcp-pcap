//
// Created by Deyu Heng on 2019-08-19.
//

#ifndef GTPV2_UTRANS_TCPPACKETCAPTURE_HPP
#define GTPV2_UTRANS_TCPPACKETCAPTURE_HPP

#include <tclDecls.h>
#include "pcap.h"


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
        printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
        sprintf(filterExp. "ip %")
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

        const u_char* pkt_data;

        int res;
        while((res = pcap_next_ex(deviceHandle, &header, &pkt_data)) >= 0){
            if(!startState) break;
            if(res == 0) continue;

            listener(header->len, pkt_data);

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
