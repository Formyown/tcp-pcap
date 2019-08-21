#ifndef GTPV2_UTRANS_UTIL_HPP
#define GTPV2_UTRANS_UTIL_HPP

class Util{
public:
    static char* getIPString(){
        return nullptr;
    }

    static void printMac(u_char* mac){
        printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    static void printHEX(const void* data,  const size_t  length){
        for(int count = 0; count < length; count++) {
            printf("%02x ", ((u_char*)data)[count]);
        }
    }



};

#endif