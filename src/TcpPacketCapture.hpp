//
// Created by Deyu Heng on 2019-08-19.
//

#ifndef GTPV2_UTRANS_TCPPACKETCAPTURE_HPP
#define GTPV2_UTRANS_TCPPACKETCAPTURE_HPP

#include "pcap.h"

struct PCAP_LIST{
    int count;

};


class TcpPacketCapture {
public:
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
