#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

void mac_address(const unsigned char* pak);
void ip_address(const unsigned char* pak);

int main(int argc, char *argv[]){

	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_ex[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
	int res;

	dev = pcap_lookupdev(errbuf);
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
	mac_address(packet);
		break; // why dont stop ! :(
	}
}


void mac_address(const unsigned char* pak){
	struct ether_header *ep;
	ep = (struct ether_header*)pak; // using ethernet.h struct "ether_header"

	printf("SOURCE : %02x:%02x:%02x:%02x:%02x:%02x \n",ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2],
			ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);
	printf("DESTINATION : %02x:%02x:%02x:%02x:%02x:%02x \n", ep->ether_dhost[0], ep->ether_dhost[1],ep->ether_dhost[2],
			ep->ether_dhost[3], ep->ether_dhost[4], ep->ether_dhost[5]);

}