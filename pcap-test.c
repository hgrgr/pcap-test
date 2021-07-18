#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap2.h"

void ck_ip_header_len(u_char *buf);
void ck_tcp_header_len(u_char *buf);
bool ck_tcp(u_char *buf);
bool pcap_print(u_char *buf);
//void cpy_eth(int start, int end, struct libnet_ethernet_hdr *eth,u_char *buf);
//void cpy_ip(int start, int end, struct libnet_ipv4 *ip, u_char *buf);
//void cpy_tcp(int start, int end, struct libnet_tcp_hdr *tcp, u_char *buf);

u_int32_t packetsize=0;
u_int8_t eth_header_len = 14;
u_int8_t ip_header_len;//4bit
u_int8_t tcp_header_len;//4bit

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		packetsize = header->caplen;
		int i=0;
		int j=0;
		if(pcap_print(packet))
		{
			packetsize = 0;
			continue;
		}
		packetsize=0;
		
	}

	pcap_close(pcap);
}
void ck_ip_header_len(u_char *buf){
	memcpy(&ip_header_len,&buf[eth_header_len],1);
	ip_header_len = (ip_header_len & 0x0F)<<2;
	//printf("\n ip_header_len = %d\n",ip_header_len);
}
void ck_tcp_header_len(u_char *buf){
	memcpy(&tcp_header_len,&buf[eth_header_len+ip_header_len+12],1);
	tcp_header_len = (tcp_header_len & 0xF0)>>2;	
	//printf("\n tcp_header_len = %d\n",tcp_header_len);
}
bool ck_tcp(u_char *buf){
	u_int16_t temp;
	memcpy(&temp,&buf[eth_header_len+9],1);

	if(temp != 0x06)//not tcp
	{
	//	printf("\nck_tcp=%.2x\n",temp);
		return false;	
	}		
	return true;
}
bool pcap_print(u_char *buf)
{
	bool payload_ck = true;
	ip_header_len = 0;//init
	tcp_header_len = 0;//init
	ck_ip_header_len(buf);
	ck_tcp_header_len(buf);
	if( packetsize == ip_header_len + tcp_header_len + eth_header_len)//not payload
	{
		payload_ck = false;
	}	
	if(!ck_tcp(buf))
	{
		printf("this is not tcp packet\n");
		return true;
	}
	/// tcp packet
	printf(" src mac = ");
	for(int i=0;i<6;i++) //eth buf - fix size
	{
		if(i==5)
			printf("%.2x",buf[i+6]);
		else
			printf("%.2x:",buf[i+6]);
	}
	printf("\n dst mac = ");
	for(int i=0;i<6;i++) //eth buf - fix size
	{
		if(i==5)
			printf("%.2x",buf[i]);
		else
			printf("%.2x:",buf[i]);
	}
		
	printf("\n src ip = " );
	for(int i=0;i<4;i++) //ip buf - fix size
	{
		if(i==3)
			printf("%d",buf[i+eth_header_len+12]);
		else
			printf("%d.",buf[i+eth_header_len+12]);
	}
	printf("\n dst ip = ");
	for(int i=0;i<4;i++) //ip buf - fix size
	{
		if(i==3)
			printf("%d",buf[i+eth_header_len + 16]);
		else
			printf("%d.",buf[i+eth_header_len + 16]);
	}
	printf("\n src port = ");
	u_int16_t portbuf;// sport print - non fix size
	memcpy(&portbuf,&buf[eth_header_len+ ip_header_len],2);
	portbuf = ntohs(portbuf);
	printf("%d",portbuf);

	printf("\n dsdt port = ");
	u_int16_t dportbuf;// dport print - non fix size
	memcpy(&dportbuf,&buf[eth_header_len + ip_header_len + 2],2);
	dportbuf = ntohs(dportbuf);
	printf("%d",dportbuf);

	
	printf("\n Payload = ");
	if(payload_ck)// payload on
	{
		for(int i=0;i<8;i++) //http hex buf - non fix size
		{
			printf("%.2x",buf[i+eth_header_len + ip_header_len + tcp_header_len]);
		}
	}
	else// no payload
	{
		printf(" No Payload");
	}
	printf("\n\n");
	return false;
}
