#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <features.h>
#include <string.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <net/if.h>
#include <ifaddrs.h>

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

//For matala 2 
struct app_header{
  uint32_t TimeStamp;
  uint16_t Length;
  uint16_t Reserved_Flags_Status_Code;
  uint16_t Cache_Control;
  uint16_t Padding;
  
} app_header;

void printBufferAsHexWithLineNumbers(const u_char *buffer, int start, int size) {
    int count = 0;
    int line = 1;
    printf("\nLine  0: ");
    for (int i = start; i < start + size; i++) {
        printf("%02x ", buffer[i]);
        count++;
        if (count == 15) {
            printf("\nLine %2d: ", line);
            count = 0;
            line++;
        }
    }
    printf("\n");
}

//
void create_txt_file(char* source_ip, char* dest_ip, int source_port, int dest_port, 
                    time_t timestamp, int total_length, uint16_t t, uint16_t cache_control,const u_char* data,int len) {
    //Extracting the flags and status code from the t parameter
    uint16_t cache_flag = (t >> 15) & 1;
    uint16_t steps_flag = (t >> 14) & 1;
    uint16_t type_flag = (t >> 13) & 1;
    uint16_t status_code = t & 0x03FF;
    // printf("source_ip: %s\n",source_ip);
    // printf("dest_ip: %s\n",dest_ip);
    // printf("source_port: %d\n",source_port);
    // printf("dest_port: %d\n",dest_port);
    // printf("timestamp: %s\n", ctime(&timestamp));
    // printf("total_length: %d\n",total_length);
    // printf("cache_flag: %d\n",cache_flag);
    // printf("steps_flag: %d\n",steps_flag);
    // printf("type_flag: %d\n",type_flag);
    // printf("status_code: %d\n",status_code);
    // printf("cache_control: %d\n",cache_control);
    // printf("data: %s\n",data);
    
    //Write the parameters to the file 
    FILE* file = fopen("208821652_208982991.txt", "a");
    if (file == NULL) {
        printf("Error creating file!\n");
        return;
    }

    fprintf(file, "source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %u, total_length: %d, cache_flag: %d, steps_flag: %d, type_flag: %d, status_code: %d, cache_control: %d Data: \n", 
            source_ip, dest_ip, source_port, dest_port, htonl(timestamp), total_length, cache_flag, steps_flag, type_flag, status_code, cache_control);
    for (int i = 0; i < len; i++)
            fprintf(file, "%02x ", (unsigned char) data[i]); 
        fprintf(file, "\n");
     fclose(file);

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
    }
    else if (ip->iph_protocol == IPPROTO_TCP)
    {
    const struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip->iph_ihl * 4));
    printf("********************************      TCP HEADER      ********************************\n");
    printf("(1) Source port           : %d\n", ntohs(tcp_header->source));
    printf("(2) Destination port      : %d\n", ntohs(tcp_header->dest));
    printf("(3) Sequence number       : %u\n", ntohl(tcp_header->seq));
    printf("(4) Acknowledgment        : %u\n", ntohl(tcp_header->ack_seq));
    printf("(5) Header length         : %d\n", tcp_header->doff*4);
    printf("(6) Urgent flag           : %d\n", tcp_header->urg);
    printf("(7) Ack flag              : %d\n", tcp_header->ack);
    printf("(8) Push flag             : %d\n", tcp_header->psh);
    printf("(9) Reset flag            : %d\n", tcp_header->rst);
    printf("(10) Synchronize flag     : %d\n", tcp_header->syn);
    printf("(11) Finish flag          : %d\n", tcp_header->fin);
    printf("(11) Window               : %d\n", ntohs(tcp_header->window));
    printf("(12) Checksum             : %d\n", ntohs(tcp_header->check));
    printf("(13) Urgent pointer       : %d\n", tcp_header->urg_ptr);
    
    
    if (tcp_header->psh == 1)
    {
      const struct app_header *app;
      app = (struct app_header*)
      (packet + sizeof(struct ether_header) + (ip->iph_ihl * 4) + (tcp_header->doff*4));
      
      printf("********************************      APP HEADER      ********************************\n");
      printf("(1) TimeStamp             : %u\n", app->TimeStamp);
      printf("(2) Length                : %u\n", app->Length);
      printf("(4) Cache_Control         : %u\n", app->Cache_Control);
      printf("********************************        PAYLOAD       ********************************\n");
     
      int totalLen = ntohs(ip->iph_len);
      int ip_hdr_len = (ip->iph_ihl * 4);
      int tcp_hdr_len = (tcp_header->doff*4);
      int app_hdr_lrn = 96;

      int dataLen = totalLen - ip_hdr_len - tcp_hdr_len - app_hdr_lrn;

      //printf("%d\n",dataLen);
      int startPoint = 16 + ip_hdr_len + tcp_hdr_len + app_hdr_lrn;
      printBufferAsHexWithLineNumbers(packet,startPoint,dataLen);
    
      create_txt_file(inet_ntoa(ip->iph_sourceip),inet_ntoa(ip->iph_destip),
      ntohs(tcp_header->source),ntohs(tcp_header->dest),(time_t)(app->TimeStamp),
      header->caplen,app->Reserved_Flags_Status_Code,app->Cache_Control,packet+startPoint,dataLen);

    }
  }
    
    
    
    
    return;
    }
}



int main(int argc,char *argv[])
{
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
      sprintf(filter_exp,"tcp");
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