#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

void ether_type_mac_address(const u_char* pak);
void ip_address(const u_char* pak, int len);
void print_data(const u_char* pak);
#define BUF 1024
#define IPv4 8
#define ARP 68

struct IP_Header{
    uint8_t version:4;
	uint8_t ihl:4;
    uint8_t tos;
	uint16_t tot_len;
	uint8_t protocol;
	uint16_t check;
	struct in_addr src;
	struct in_addr dec;
	uint16_t sport;
	uint16_t dport;
}__attribute__((packed));

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
	pak_offset = 19;
	ip_address(packet, pak_offset);
	print_data(packet);
	break;

	}
}


void ether_type_mac_address(const u_char* pak){
	struct	mac_ether{
	u_char	dmac[6];
	u_char	smac[6];
	u_short	type;
};
	struct mac_ether *ep;
	ep = (struct mac_ether*)pak;

	printf("------------------MAC-------------------- \n");
	printf("SOURCE : %02X:%02X:%02X:%02X:%02X:%02X \n",ep->smac[0], ep->smac[1], ep->smac[2],
			ep->smac[3], ep->smac[4], ep->smac[5]);
	printf("DESTINATION : %02X:%02X:%02X:%02X:%02X:%02X \n", ep->dmac[0], ep->dmac[1],ep->dmac[2],
			ep->dmac[3], ep->dmac[4], ep->dmac[5]);
	printf("--------------ETHER_TYPE----------------- \n");
	switch(ep->type){
		case IPv4:
			printf("IPv4 Type Packet \n");
			break;
		case ARP:
			printf("ARP Type Packet \n");
			break;
		default:
			printf("None \n");
	}
}

void ip_address(const u_char* pak, int len){
	char so_ip[16];
	char de_ip[16];
	struct IP_Header *source;
	pak+=len;
	source = (struct IP_Header*)pak;

	inet_ntop(AF_INET, &source->src, so_ip, sizeof(so_ip));
	inet_ntop(AF_INET, &source->dec, de_ip, sizeof(de_ip));

	printf("------------------IP_Heaer--------------- \n");
	printf("SOURCE : %s \n", so_ip);
	printf("DESTINATION : %s \n", de_ip);
	printf("SOURCE PORT : %d \n", ntohs(source->sport));
	printf("DESTINATION PORT : %d \n", ntohs(source->dport));
}

void print_data(const u_char* pak){
	printf("------------------PACKET_DATA------------ \n");
	for(int i=0; i<BUF; i++){
		printf("%02X ", pak[i]);
		if(i%15==1)
			printf("\n");
	}
}















