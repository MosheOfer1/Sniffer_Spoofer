#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <features.h>
#include <string.h>
#include <linux/filter.h>
#include <net/if.h>
#include <ifaddrs.h>
#include<sys/wait.h>

#define PACKET_LEN 512

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
}; 

struct sock_filter code[] = {
  { 0x28,  0,  0, 0x0000000c }, { 0x15,  0,  8, 0x000086dd },
  { 0x30,  0,  0, 0x00000014 }, { 0x15,  2,  0, 0x00000084 },
  { 0x15,  1,  0, 0x00000006 }, { 0x15,  0, 17, 0x00000011 },
  { 0x28,  0,  0, 0x00000036 }, { 0x15, 14,  0, 0x00000016 },
  { 0x28,  0,  0, 0x00000038 }, { 0x15, 12, 13, 0x00000016 },
  { 0x15,  0, 12, 0x00000800 }, { 0x30,  0,  0, 0x00000017 },
  { 0x15,  2,  0, 0x00000084 }, { 0x15,  1,  0, 0x00000006 },
  { 0x15,  0,  8, 0x00000011 }, { 0x28,  0,  0, 0x00000014 },
  { 0x45,  6,  0, 0x00001fff }, { 0xb1,  0,  0, 0x0000000e },
  { 0x48,  0,  0, 0x0000000e }, { 0x15,  2,  0, 0x00000016 },
  { 0x48,  0,  0, 0x00000010 }, { 0x15,  0,  1, 0x00000016 },
  { 0x06,  0,  0, 0x0000ffff }, { 0x06,  0,  0, 0x00000000 },
};


struct sock_fprog bpf = {

	.len = sizeof(code) / sizeof((code)[0]),
	.filter = code,
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader* ip)
{
    //struct sockaddr_in r_addr;
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    //printf("%ld\n",
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));

    close(sock);
}

int counter = 0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ether_header *eth = (struct ether_header *)packet;
  printf("\n\n\n********************************     Packet Num: %d     ********************************\n",++counter);
  printf("(1) Total size            : %d\n",header->caplen);
  printf("\n********************************      ETH HEADER      ********************************\n");
  printf("(1) Sourch MAC Adress     : %s\n", ether_ntoa((const struct ether_addr *)eth->ether_shost));
  printf("(2) Destenation MAC Adress: %s\n", ether_ntoa((const struct ether_addr *)eth->ether_dhost));
  printf("(3) Type                  : %u\n", ntohs(eth->ether_type));
  
    
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ether_header)); 

    printf("********************************      IP HEADER       ********************************\n");
    
    // print the fields
    printf("(1) IP header length      : %d\n", ip->iph_ihl);
    printf("(2) IP version            : %d\n", ip->iph_ver);
    printf("(3) Type of service       : %d\n", ip->iph_tos);
    printf("(4) IP Packet length      : %d\n", ntohs(ip->iph_len));
    printf("(5) Identification        : %d\n", ntohs(ip->iph_ident));
    printf("(6) Fragmentation flags   : %d\n", ip->iph_flag);
    printf("(7) Flags offset          : %d\n", ip->iph_offset);
    printf("(8) Time to Live          : %d\n", ip->iph_ttl);
    printf("(9) Protocol type         : ");
   
    /* determine protocol */
    if ((ip->iph_protocol) == IPPROTO_TCP)
    {
      printf("TCP\n");
    }
     if ((ip->iph_protocol) == IPPROTO_UDP)
    {
      printf("UDP\n");
    }
     if ((ip->iph_protocol) == IPPROTO_ICMP)
    {
      printf("ICMP\n");
    }
    

    printf("(10) IP checksum          : %d\n", ntohs(ip->iph_chksum));
    printf("(11) Source IP address    : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("(12) Dest IP address      : %s\n", inet_ntoa(ip->iph_destip));
    if (ip->iph_protocol == IPPROTO_ICMP)
    {
      struct icmpheader  *icmp = (struct icmpheader *)
                           (packet + sizeof(struct ether_header) + (ip->iph_ihl * 4)); 
      printf("********************************      ICMP HEADER      ********************************\n");
      printf("ICMP Header Details:\n");
      printf("(1) Type:    %u\n", icmp->icmp_type);
      printf("(2) Code:    %u\n", icmp->icmp_code);
      printf("(3) Checksum:%u\n", icmp->icmp_chksum);
      printf("(4) Id:      %u\n", icmp->icmp_id);
      printf("(5) Seq:     %u\n", icmp->icmp_seq);

    if (icmp->icmp_type == 8)
    {
        icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

        // Calculate the checksum for integrity
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                        sizeof(struct icmpheader));
        // Replace the dest and the src
        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_ttl = 20;
        in_addr_t temp = inet_addr(inet_ntoa(ip->iph_sourceip));
        ip->iph_sourceip.s_addr = inet_addr(inet_ntoa(ip->iph_destip));
        ip->iph_destip.s_addr = temp;

        send_raw_ip_packet (ip);
    }
    }
return;
  }
}



int main(int argc,char *argv[])
{
    // The user enter up to 2 arguments, the [protocol] [where to listen]
    // Defult is "icmp" and "enp0s3"
    char interf[100];
    char filter_exp[100];
    if (argc > 3)
    {
        printf("usage: [protocol] [where to listen]\n");
        exit(-1);
    }
   
  if (argc > 1)
  {
    sprintf(filter_exp,"%s",argv[1]);
  }
  else 
      sprintf(filter_exp,"icmp");
  if (argc == 3)
  {
    sprintf(interf,"%s",argv[2]);
  }
  else 
      sprintf(interf,"enp0s3");
 
  
  
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name waln0 
  handle = pcap_open_live(interf, BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                
  pcap_close(handle);   //Close the handle 
  return 0;
}