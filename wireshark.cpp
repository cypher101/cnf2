#include<pcap.h>
#include<stdio.h>
#include<net/ethernet.h>
#include<netinet/ip.h>    //Provides declarations for ip header
Void process_packet(u_char *, conststructpcap_pkthdr *, constu_char *);
inttcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
int main()
{
charerrbuf[PCAP_ERRBUF_SIZE];
    //Open the pcapwireshark file
	pcap_t *handle = pcap_open_offline("d.gz.pcap", errbuf);
    //Put the device in sniff loop
pcap_loop(handle , -1 , process_packet , NULL);
printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
return 0;   
}
voidprocess_packet(u_char *args, conststructpcap_pkthdr *header, constu_char *buffer)
{
int size = header->len;
    //Get the IP Header part of this packet , excluding the ethernet header
structiphdr *iph = (structiphdr*)(buffer + sizeof(structethhdr));
    ++total;
switch (iph->protocol) //Check the Protocol and do accordingly...
    {
case 1:  //ICMP Protocol
            ++icmp;
break;

case 2:  //IGMP Protocol
            ++igmp;
break;

case 6:  //TCP Protocol
            ++tcp;
            //print_tcp_packet(buffer , size);
break;

case 17: //UDP Protocol
            ++udp;
            //print_udp_packet(buffer , size);
break;

default: //Some Other Protocol like ARP etc.
            ++others;
break;
    }
printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);}
