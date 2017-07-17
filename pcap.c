#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>

struct mac_address {
	u_int8_t shost[6];
	u_int8_t dhost[6];
}__attribute__ ((__packed__));

struct ip_address {
	u_int8_t sadd[4];
	u_int8_t dadd[4];
}__attribute__ ((__packed__));

struct port {
	uint16_t sport;
	uint16_t dport;

}__attribute__ ((__packed__));

int main(int argc, char *argv[]){
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;	
	char filter_exp[] = "";
	bpf_u_int32 mask;
	bpf_u_int32 net;	
	struct pcap_pkthdr header;
	const u_char *packet;
	struct mac_address *mac;
	struct ip_address *ip;
	struct port *pt;
	char *data;
	int res;
	/*char s_ip[6]*/
	dev = pcap_lookupdev(errbuf);
	
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
		
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
		
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
		
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
		
	packet = pcap_next(handle, &header);
		
	mac = (struct mac_address*)packet;
	pt = (struct port*)packet;
	ip = (struct ip_address*)packet;
	data = (char*)packet+34;
	printf("SOURCE MAC %02x:%02x:%02x:%02x:%02x:%02x \n", 
	mac->shost[0], mac->shost[1], mac->shost[2], mac->shost[3],
	mac->shost[4], mac->shost[5]);
		
	printf("DESTINATION MAC %02x:%02x:%02x:%02x:%02x:%02x \n",
	mac->dhost[0], mac->dhost[1], mac->dhost[2], mac->dhost[3],
	mac->dhost[4], mac->dhost[5]);
	
	printf("SOURCE IP : %d.%d.%d.%d \n", ip->sadd[0], ip->sadd[1]
	, ip->sadd[2], ip->sadd[3]);
	printf("DESTINATION IP : %d.%d.%d.%d \n", ip->dadd[0], ip->dadd[1]
	, ip->dadd[2], ip->dadd[3]);
	printf("SOURCE PORT : %d \n", pt->sport);
	printf("DESTINATION PORT : %d \n", pt->dport);
	memcpy(data, packet, 1024);
	/*for(int i=36; i<1024; i++){
		printf("%02x ", data[i]);
		if(i%16==0)
			printf("\n");				//packet data print
	}
	printf("\n");*/
	
	/*printf("DESTINATION IP : %s \n", inet_ntoa(ip->dadd));
	printf("SOURCE PORT : %d \n", port->th_sport);*/
	/*printf("DESTINATION PORT : %d \n",port->th_dport);*/
	/*printk(KERN_DEBUG, "%pI4", &ip->saddr);*/
	/*memcpy(s_ip, &ip->saddr, 16);*/
	/*snprintf(s_ip, 16, "%pI4", &ip->saddr);*/
	pcap_close(handle);
	
	return(0);
}
