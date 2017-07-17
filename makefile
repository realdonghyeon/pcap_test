all: pcap_test
pcap_test: pcap.c
	gcc -o pcap pcap.c -lpcap
clean:
	rm pcap
