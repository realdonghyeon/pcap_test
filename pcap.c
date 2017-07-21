#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
void ether_type_mac_address(const u_char* pak);
void ip_address(const u_char* pak, int len);

#define BUF 256
#define IPv4 0x0800
#define ARP 0x0806

struct iphdr{
    uint8_t version:4;
	uint8_t ihl:4;
    uint8_t tos;
	uint16_t tot_len;
	uint8_t protocol;
	uint16_t check;
	struct in_addr src;
	struct in_addr dec;
	u_long sport;
	u_long dport;
};

int main(int argc, char *argv[]){
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	char data[BUF];
	struct bpf_program fp;
	char filter_ex[] = "";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet = data;
	int res;
	int pak_offset = 0;

	dev = argv[1];
	if(dev == NULL){
		printf("Error %s \n", errbuf);
		return(2);
	}
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		printf("error device %s: %s \n",dev, errbuf);
		net=0;
		mask=0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		printf("%s : %s \n", dev, errbuf);
		return(2);
	}
	if(pcap_compile(handle, &fp, filter_ex, 0, net) == -1){
		printf("%s : %s \n", filter_ex, pcap_geterr(handle));
		return(2);
	}
	if(pcap_setfilter(handle, &fp) == -1){
		printf("%s : %s\n", filter_ex, pcap_geterr(handle));
		return(2);
	}

	while((res=pcap_next_ex(handle, &header, &packet))>=0){
		if(res==0) 
			continue;

	ether_type_mac_address(packet);
	pak_offset = 18;
	ip_address(packet, pak_offset);
		break;
	}
}


void ether_type_mac_address(const u_char* pak){
	struct ether_header *ep;
	ep = (struct ether_header*)pak; // using ethernet.h struct "ether_header"

	printf("------------------MAC--------------------- \n");
	printf("SOURCE : %02X:%02X:%02X:%02X:%02X:%02X \n",ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2],
			ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);
	printf("DESTINATION : %02X:%02X:%02X:%02X:%02X:%02X \n", ep->ether_dhost[0], ep->ether_dhost[1],ep->ether_dhost[2],
			ep->ether_dhost[3], ep->ether_dhost[4], ep->ether_dhost[5]);
	printf("------------------MAC--------------------- \n");
	switch(ep->ether_type){
		case 8:
			printf("IPv4 Type Packet \n");
			break;
		case ARP:
			printf("ARP Type Packet \n");
			break;
	}
}

void ip_address(const u_char* pak, int len){
	char so_ip[16];
	char de_ip[16];
	char so_pt[2];
	char de_pt[2];
	/*struct iphdr *add;*/
	struct iphdr *source;
	pak+=len;
	source = (struct ip*)pak;
	/*add = (struct iphdr*)pak*/
	inet_ntop(AF_INET, &source->src, so_ip, sizeof(so_ip));
	inet_ntop(AF_INET, &source->dec, de_ip, sizeof(de_ip));
	inet_ntop(AF_INET, &source->sport, so_pt, sizeof(so_pt));
	inet_ntop(AF_INET, &source->dport, de_pt, sizeof(de_pt));
	printf("------------------IP---------------------- \n");
	printf("SOURCE : %s \n", so_ip);
	printf("DESTINATION : %s \n", de_ip);
	printf("%s \n", so_pt);
	printf("------------------IP---------------------- \n");
}