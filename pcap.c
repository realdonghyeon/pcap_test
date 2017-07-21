#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void mac_address(const u_char* pak);
void ip_address(const u_char* pak, int len);

#define BUF 256

struct iphdr{
    u_int8_t version:4;
	u_int8_t ihl:4;
    u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_long s_ip;
	u_long d_ip;
}__attribute__((packed));

int main(int argc, char *argv[]){
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	char data[BUF];
	struct bpf_program fp;
	char filter_ex[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet = data;
	int res;
	int pat_offset = 0;

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
		if(res==0 || -1) 
			continue;

	mac_address(packet);
	pat_offset = 22;
	ip_address(packet, pat_offset);
		break;
	}
}


void mac_address(const u_char* pak){
	struct ether_header *ep;
	ep = (struct ether_header*)pak; // using ethernet.h struct "ether_header"

	printf("SOURCE : %02X:%02X:%02X:%02X:%02X:%02X \n",ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2],
			ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);
	printf("DESTINATION : %02X:%02X:%02X:%02X:%02X:%02X \n", ep->ether_dhost[0], ep->ether_dhost[1],ep->ether_dhost[2],
			ep->ether_dhost[3], ep->ether_dhost[4], ep->ether_dhost[5]);
}

void ip_address(const u_char* pak, int len){
	char ip[16];
	/*struct iphdr *add;*/
	struct iphdr *source;
	pak+=len;
	source = (struct iphdr*)pak;
	/*add = (struct iphdr*)pak*/ 
	inet_ntop(AF_INET, &source->s_ip, ip, sizeof(ip));
	printf("SOURCE : %s \n", ip);
}