#include <stdlib.h> 
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>  // IP 함수변환을 위한 함수 제공
#include <netinet/ether.h> // MAC주소 변환을 위한 함수 제공


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,     // IP header length - 4byte 단위임
                     iph_ver:4;     // IP version
  unsigned char      iph_tos;       // Type of service
  unsigned short int iph_len;       // IP Packet length (data + header)
  unsigned short int iph_ident;     // Identification
  unsigned short int iph_flag:3,    // Fragmentation flags
                     iph_offset:13; // Flags offset
  unsigned char      iph_ttl;       // Time to Live
  unsigned char      iph_protocol;  // Protocol type
  unsigned short int iph_chksum;    // IP datagram checksum
  struct  in_addr    iph_sourceip;  // Source IP address
  struct  in_addr    iph_destip;    // Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;            // source port - 16bit
    u_short tcp_dport;            // destination port - 16bit 
    u_int   tcp_seq;              // sequence number - 32bbit 
    u_int   tcp_ack;              // acknowledgement number - 32bite 
    u_char  tcp_offx2;            // data offset, rsvd  - 4byte 단위임
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;            // each 1bit -> 8bit
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;               // window - 16bit
    u_short tcp_sum;               // checksum - 16bit
    u_short tcp_urp;               // urgent pointer - 16bit
};

// 패킷의 헤더 정보 추출, 콜백함수
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{

  // ethernet header address
  struct ethheader *eth = (struct ethheader *)packet;
  // ip header address = ethernet header address + ethernet header size
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  // tcp header address = ethernet header address + ethernet header size + ip header size
  struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
  
  // 0x0800 -> IP (IPv4) and TCP 
  if ((ntohs(eth->ether_type) == 0x0800 && ip->iph_protocol == IPPROTO_TCP)) {

    printf("\n=== Ethernet ===\n");
    printf("MAC From: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));   
    printf("MAC To: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));  
    
    printf("\n=== IP ===\n");
    printf("IP From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("IP To: %s\n", inet_ntoa(ip->iph_destip));   
    
    printf("\n=== TCP ===\n");
    printf("PORT From: %d\n", ntohs(tcp->tcp_sport));   
    printf("PORT To: %d\n", ntohs(tcp->tcp_dport));  


    
    // message 출력
    int ip_header_len = ip->iph_ihl * 4; 
    int tcp_header_len = TH_OFF(tcp) * 4;
    int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    if (payload_len > 0) {
        printf("\n=== message (최대 100바이트) ====\n");
        
        int print_len = (payload_len > 100) ? 100 : payload_len;  // 최대 100바이트만 출력
        const u_char *payload = packet + payload_offset;

        // 16진수 출력
        printf("HEX: ");
        for (int i = 0; i < print_len; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n");

        // ASCII 출력
        printf("ASCII: ");
        for (int i = 0; i < print_len; i++) {
            char c = payload[i];
            if (c >= 32 && c <= 126) { // 출력 가능한 문자 범위
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        printf("\n");
    } else {
        printf("\n=== message 없음 ===\n");
    }
    
    printf("---------------------------------\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE]; 
  struct bpf_program fp;   
  char filter_exp[] = "tcp"; 
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);


  // Step 2: Compile filter_exp into BPF psuedo-code 
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

 
  // 캡쳐 종료
  pcap_close(handle);   //Close the handle
  return 0;
}
