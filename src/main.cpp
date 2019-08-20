#include <iostream>

#include "TcpPacketCapture.hpp"

using namespace std;
int PacketHandler(int len, const u_char* data){
 cout << len << endl;
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

    TcpPacketCapture tcpPacketCapture("en0", 0);

    tcpPacketCapture.StartListen(PacketHandler);

    tcpPacketCapture.StopListen();
}