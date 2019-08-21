//
// Created by System Administrator on 2019-08-20.
//

#ifndef GTPV2_UTRANS_PACKET_H
#define GTPV2_UTRANS_PACKET_H

#ifndef _PACKETS_H_
#define _PACKETS_H_


#define Ethernet_TYPE_IPv4 (0x0800)
#define Ethernet_TYPE_ARP (0x0806)
#define INERNETPROTOCOL_PROTOCOL_UDP (0x11)
#define INERNETPROTOCOL_PROTOCOL_TCP (0x06)

#ifdef __GNUC__
#ifdef __MINGW32__
    /* gcc 4.7 miscompiles packed structures in MS-bitfield mode */
#define PACKED __attribute__((packed, gcc_struct, aligned(1)))
#else
#define PACKED __attribute__((packed, aligned(1)))
#endif
#else
#error "Need to define PACKED for this compiler"
#endif

    typedef uint16_t pk_big_uint16;
    typedef uint32_t pk_big_uint32;

// #pragma pack(push)
// #pragma pack(1)
    typedef struct
    {
        u_char DstMac[6];
        u_char SrcMac[6];
        pk_big_uint16 Type;
    } PACKED Ethernet, *PEthernet;

    typedef struct
    {
        u_char HeaderLength : 4;
        u_char Version : 4;

        struct
        {
            u_char Ecn : 2;
            u_char Dscp : 6;
        } DSField;

        pk_big_uint16 TotalLength;
        pk_big_uint16 Identification;
        struct
        {
            pk_big_uint16 FragOffset : 13;
            u_char Mf : 1;
            u_char Df : 1;
            u_char Rb : 1;
        } Flags;
        u_char TTL;
        u_char Protocol;
        pk_big_uint16 Checksum;
        u_char SrcIP[4];
        u_char DstIP[4];
    } PACKED InernetProtocol, *PInernetProtocol;

    typedef struct
    {
        pk_big_uint16 SrcPort;
        pk_big_uint16 DstPort;
        pk_big_uint16 Length;
        pk_big_uint16 Unknown;
    } PACKED UDP, *PUDP;

    typedef struct
    {
        struct
        {
            u_char PNP : 1;
            u_char SNP : 1;
            u_char NEHP : 1;
            u_char Reserved : 1;
            u_char Payload : 1;
            u_char Version : 3;
        } Flags;
        u_char MessageType;
        pk_big_uint16 Length;
        uint32_t TEID;
    } PACKED GTP, *PGTP;

    typedef struct {
        pk_big_uint16 SrcPort : 16;
        pk_big_uint16 DstPort : 16;
        pk_big_uint32 SeqNum : 32;
        pk_big_uint32 AckNum : 32;

        u_char NS : 1;
        u_char Reserved : 3;
        u_char HeaderLen : 4;

        u_char FIN : 1;
        u_char SYN : 1;
        u_char RST : 1;
        u_char PSH : 1;
        u_char ACK : 1;
        u_char URG : 1;
        u_char ECE : 1;
        u_char CWR : 1;

        pk_big_uint16 WndSize : 16;
        pk_big_uint16 Checksum : 16;
        pk_big_uint16 UrgentPtr : 16;
    } PACKED TCP, *PTCP;

// #pragma pack()
// #pragma pack(pop)

    typedef const PEthernet CPEthernet;
    typedef const PInernetProtocol CPInernetProtocol;
    typedef const PUDP CPUDP;
    typedef const PGTP CPGTP;
    typedef const PTCP CPTCP;
#define SIZEOF_ETHERNET (sizeof(Ethernet))
#define SIZEOF_INERNETPROTOCOL (sizeof(InernetProtocol))
#define SIZEOF_UDP (sizeof(UDP))
#define SIZEOF_GTP (sizeof(GTP))
#define SIZEOF_TCP(ptcp) ((ptcp)->HeaderLen * 4)

    CPEthernet decode_Ethernet(const u_char *buf, uint16_t desiredType, u_char **payload);
    CPInernetProtocol decode_InernetProtocol(const u_char *buf, u_char desiredVersion, u_char desiredProtocol, u_char **payload);
    CPUDP decode_UDP(const u_char *buf, uint16_t desiredSrcPort, uint16_t desiredDstPort, u_char **payload);
    CPGTP decode_GTP(const u_char *buf, u_char desiredVersion, u_char **payload);
    CPTCP decode_TCP(const u_char *buf, u_char **options, u_char **payload);

#endif

#endif //GTPV2_UTRANS_PACKET_H
