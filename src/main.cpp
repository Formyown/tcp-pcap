#include <iostream>

#include "TcpPacketCapture.hpp"
#include "Util.hpp"


using namespace std;

int PacketHandler(int len, const u_char* data){

}

int main() {

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

    TcpPacketCapture::FreeDeviceList(deviceList);

    in_addr ip{0};
    inet_aton("192.168.1.102", &ip);
    TcpPacketCapture tcpPacketCapture("en0", ip.s_addr);

    tcpPacketCapture.StartListen(PacketHandler);

    tcpPacketCapture.StopListen();
}