#include <iostream>

#include "TcpPacketCapture.hpp"

using namespace std;

int main() {
    //TcpPacketCapture tcpPacketCapture;
    pcap_if_t* deviceList = TcpPacketCapture::GetDeviceList();

    for(auto d = deviceList; d; d = d->next)
    {
        static int i = 0;
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    pcap_t *adhandle;
    char error[128];
    /* 打开设备 */
    if ( (adhandle= pcap_open_live("en0",            // 设备名
                                   65536,            // 要捕捉的数据包的部分
                                   true,             // 混杂模式
                                   1000,             // 读取超时时间
                                   error             // 错误缓冲池
    ) ) == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", "en0", error);
        return(2);
    }

    printf("\nlistening on %s...\n","en0");

    struct pcap_pkthdr *header;
    int res;
    const u_char *pkt_data;
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0) continue;



        printf("Time:%ld len:%d caplen:%d comment:%s\n", header->ts.tv_usec, header->len, header->caplen, header->comment);
    }

    TcpPacketCapture::FreeDeviceList(deviceList);
}