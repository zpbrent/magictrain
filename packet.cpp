/*
 * packet class for parsing TCP/IP packets
 * only support IPv4 now!!!
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "packet.h"
#include "log.h"

#include <iostream>
#include <iomanip>

extern Log* logger;

/* Constructor */
Packet::Packet(const uint8_t *b, uint16_t len, struct timespec t)
{
   build_pkt(b, len);
   ts = t;
   len_ = len;
}

Packet::Packet()
{
   reset();
}

/* Destructor */
Packet::~Packet()
{
}

/* The basic function for basic CheckSum calculation */
int Packet::in_cksum_(uint16_t *addr, int len)
{
    int sum = 0;
    while (len > 1) 
    {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) 
    {
        sum += *(uint16_t *)addr;
    }
    return (sum);
}

/* 
  Dug Song came up with this very cool checksuming implementation 
 * eliminating the need for explicit psuedoheader use. 
 * http://72.52.208.92/~gbpprorg/w00w00/files/sectools/fragrouter/Libnet-0.99b/src/checksum.c
 * We check it out for use.
*/
int Packet::do_checksum_(int protocol)
{
   int sum = 0;
   switch (protocol) 
   {
      case IPPROTO_TCP:
	 tcp_hdr->check = 0;
	 sum = in_cksum_((u_short *)&ip_hdr->ip_src, 8);
	 sum += ntohs(IPPROTO_TCP + get_ip_payload_len());
	 sum += in_cksum_((u_short *)tcp_hdr, get_ip_payload_len());
	 tcp_hdr->check = CKSUM_CARRY(sum);
	 break;		   
      case IPPROTO_ICMP:
         icmp_hdr->checksum = 0;
         sum += in_cksum_((uint16_t *)(icmp_hdr), get_ip_payload_len());
         icmp_hdr->checksum = CKSUM_CARRY(sum);
         break;
      case IPPROTO_IP:
	 ip_hdr->ip_sum = 0;
	 sum = in_cksum_((u_short *)ip_hdr, get_ip_hdr_len());
	 ip_hdr->ip_sum = CKSUM_CARRY(sum);
	 break;    
      default:
	 logger->PrintErr("[%s:%d] Unsupported protocol\n", __FILE__, __LINE__);
         return -1;
    }
    return 0;
}

bool Packet::is_tcp() 
{ 
   return (ip_hdr->ip_p == IPPROTO_TCP); 
}

bool Packet::is_icmp() 
{
   return (ip_hdr->ip_p == IPPROTO_ICMP); 
}

bool Packet::is_icmp_ttl_exceeded() 
{
   if (!is_icmp())
   {
      return false;
   }
   else
   {
      if (icmp_hdr->type != 11)
      {
	 return false;
      }
      else
      {
	 return true;
      }
   }
}

bool Packet::is_tcp_fin() 
{ 
   return is_tcp() && tcp_hdr->fin > 0; 
}

bool Packet::is_tcp_syn() 
{
   return is_tcp() && tcp_hdr->syn > 0; 
}

bool Packet::is_tcp_rst() 
{
   return is_tcp() && tcp_hdr->rst > 0; 
}

bool Packet::is_tcp_psh() 
{ 
   return is_tcp() && tcp_hdr->psh > 0; 
}

bool Packet::is_tcp_ack() 
{ 
   return is_tcp() && tcp_hdr->ack > 0; 
}

bool Packet::is_tcp_urg() 
{ 
   return is_tcp() && tcp_hdr->urg > 0; 
}

struct timespec Packet::get_ts() 
{ 
   return ts; 
}

struct ip* Packet::get_ip_hdr() 
{ 
   return ip_hdr; 
}

uint16_t Packet::get_ip_len() 
{ 
   return ntohs(ip_hdr->ip_len); 
}

uint16_t Packet::get_ip_hdr_len() 
{ 
   return ip_hdr->ip_hl<<2; 
}


uint16_t Packet::get_ip_payload_len() 
{ 
   return get_ip_len()-get_ip_hdr_len(); 
} 

uint8_t* Packet::get_ip_pkt_buf() 
{ 
   return buf_; 
}							

uint32_t Packet::get_sip() 
{ 
   return ip_hdr->ip_src.s_addr; 
}

uint32_t Packet::get_dip() 
{ 
   return ip_hdr->ip_dst.s_addr; 
}

uint8_t Packet::get_ip_ttl() 
{ 
   return ip_hdr->ip_ttl; 
}

uint8_t Packet::get_ip_protocol() 
{ 
   return ip_hdr->ip_p; 
}

uint16_t Packet::get_ip_id() 
{ 
   return ntohs(ip_hdr->ip_id); 
}

uint16_t Packet::get_tcp_payload_len() 
{ 
   return (is_tcp())?(get_ip_len()-get_ip_hdr_len()-get_tcp_hdr_len()):0; 
}

struct tcphdr* Packet::get_tcp_hdr() 
{ 
   return tcp_hdr;
}

uint16_t Packet::get_tcp_hdr_len() 
{ 
   return tcp_hdr->doff<<2; //tcp_hdr + tcp option
}		

uint16_t Packet::get_tcp_sport_raw() 
{
   return tcp_hdr->source; 
}

uint16_t Packet::get_tcp_sport() 
{ 
   return ntohs(tcp_hdr->source); 
}

uint16_t Packet::get_tcp_dport_raw() 
{ 
   return tcp_hdr->dest; 
}

uint16_t Packet::get_tcp_dport() 
{ 
   return ntohs(tcp_hdr->dest); 
}

uint32_t Packet::get_tcp_seq() 
{ 
   return ntohl(tcp_hdr->seq); 
}

uint32_t Packet::get_tcp_ack() 
{ 
   return ntohl(tcp_hdr->ack_seq); 
}

uint16_t Packet::get_tcp_win() 
{ 
   return tcp_hdr->window; 
}

uint16_t Packet::get_tcp_opt_len() 
{ 
   return (tcp_hdr->doff<<2)-TCP_H; 
}

uint8_t* Packet::get_tcp_opt() 
{ 
   return (uint8_t*)tcp_hdr + TCP_H; 
}

void Packet::reset()
{
   memset(buf_, 0, BUF_SIZE);
   len_ = 0;
   memset(&ts, 0, sizeof(struct timespec));
   ip_hdr = NULL;
   tcp_hdr = NULL;
   icmp_hdr = NULL;
   payload = NULL;
}

/* for constructing a packet that is captured */
void Packet::build_pkt(const uint8_t *b, uint16_t len) 
{
   reset();
   memcpy(buf_, b, len);
   payload = buf_;
   ip_hdr = (struct ip*)buf_;
   if(is_tcp()) 
   {
      tcp_hdr = (struct tcphdr*)((uint8_t *)(ip_hdr) + get_ip_hdr_len());
      set_payload((uint8_t *)((uint8_t *)(tcp_hdr) + get_tcp_hdr_len()));
   } 
   else if (is_icmp()) 
   {
      icmp_hdr = (struct icmphdr*)((uint8_t *)(ip_hdr) + get_ip_hdr_len());
      set_payload((uint8_t *)((uint8_t *)(icmp_hdr) + ICMP_H));
   } 
   else 
   {
      logger->PrintErr("[%s:%d] Only support TCP/ICMP/IP now!\n", __FILE__, __LINE__);
   }
}

void Packet::set_ts(struct timespec t) 
{ 
   ts = t; 
}

void Packet::set_payload(uint8_t* p) 
{ 
   payload=p; 
}

void Packet::reset_ip_hdr_checksum() 
{ 
   ip_hdr->ip_sum=0; 
}

void Packet::update_ip_len_(uint16_t l) 
{
   ip_hdr->ip_len = htons(get_ip_len() + l);
   len_ = len_ + l;
}

void Packet::build_ip_hdr_(uint16_t id, uint8_t ttl, uint32_t src, uint32_t dst) 
{
   ip_hdr = (struct ip*)buf_;
   ip_hdr->ip_hl = 5;					//20 bytes
   ip_hdr->ip_v = IPVER;
   ip_hdr->ip_tos = 0;
   ip_hdr->ip_id = htons(id);
   ip_hdr->ip_off = htons(IP_DF);
   ip_hdr->ip_ttl = ttl;
   ip_hdr->ip_p = 0;
   ip_hdr->ip_sum = 0;
   ip_hdr->ip_src.s_addr = src;
   ip_hdr->ip_dst.s_addr = dst;
   update_ip_len_(IPV4_H);	//include the IP header len to the ip_len
}

void Packet::update_tcp_flag_(uint8_t flag) 
{
   if(flag&TH_FIN) 
   {
      tcp_hdr->fin=1;
   }
   if(flag&TH_SYN) 
   {
      tcp_hdr->syn=1;
   }
   if(flag&TH_RST) 
   {
      tcp_hdr->rst=1;
   }
   if(flag&TH_PUSH) 
   {
      tcp_hdr->psh=1;
   }
   if(flag&TH_ACK) 
   {
      tcp_hdr->ack=1;
   }
   if(flag&TH_URG) 
   {
      tcp_hdr->urg=1;
   }
}

void Packet::update_tcp_off_(uint16_t l) 
{
   uint32_t i, j;
   
   if(l>0) 
   {
      for (i=0,j=0; i<l; i++) 
      {
	 (i%4) ? j : j++;
      }
      tcp_hdr->doff += j;
   }
}
							       

void Packet::build_tcp_hdr_(uint16_t sp, uint16_t dp, uint32_t seq, \
			      uint32_t ack, uint16_t win, uint8_t flag) 
{
   tcp_hdr = (struct tcphdr *)(buf_+IPV4_H);
   tcp_hdr->source = htons(sp);
   tcp_hdr->dest = htons(dp);
   tcp_hdr->seq = htonl(seq);
   tcp_hdr->ack_seq = htonl(ack);
   tcp_hdr->res1 = 0;
   tcp_hdr->res2 = 0;
   tcp_hdr->window = htons(win);
   tcp_hdr->check = 0;
   tcp_hdr->urg_ptr = 0;

   ip_hdr->ip_p = IPPROTO_TCP;
   update_tcp_flag_(flag);				//include the tcp flag
   update_tcp_off_(TCP_H);				//include the TCP header len to doff
   update_ip_len_(TCP_H);				//include the TCP header len to ip_len
   set_payload(buf_ + IPV4_H + TCP_H);			//update the pointer to the TCP payload
}


void Packet::build_tcp_option_(uint8_t *opt, uint16_t len) 
{
   uint16_t opt_len;
   opt_len = len;
   if(opt_len%4) 
   {
      opt_len = 4 - (opt_len%4);			//add padding
   }
   memcpy(payload, opt, opt_len);
   update_tcp_off_(opt_len);				//include the TCP option len to doff
   update_ip_len_(opt_len);				//include the TCP option len to ip_len
   set_payload(payload + opt_len);			//update the pointer to the TCP payload
}


void Packet::build_icmp_hdr_(uint8_t type, uint8_t code, uint16_t id, uint16_t seq) 
{
   icmp_hdr = (struct icmphdr*)(buf_+IPV4_H);
   icmp_hdr->type=type;
   icmp_hdr->code=code;
   icmp_hdr->checksum=0;
   icmp_hdr->un.echo.id=htons(id);
   icmp_hdr->un.echo.sequence=htons(seq);
   ip_hdr->ip_p = IPPROTO_ICMP;
   update_ip_len_(ICMP_H);				//include the ICMP header len to ip_len
   set_payload(buf_ + IPV4_H + ICMP_H);			//update the pointer to the ICMP payload
}

void Packet::build_payload_(uint8_t *p, uint16_t len) 
{
	memcpy(payload, p, len);
	update_ip_len_(len);				//include the payload len to ip_len
}

/* build a TCP packet */
void Packet::build_tcp_pkt(uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_sp, uint16_t tcp_dp, \
		uint32_t tcp_seq, uint32_t tcp_ack, uint16_t ip_id, uint8_t ip_ttl, \
		uint16_t tcp_win, uint8_t tcp_flag, uint16_t tcp_mss, uint32_t tcp_tsval, \
		uint32_t tcp_tsecr, uint8_t *tcp_payload, uint16_t tcp_payload_len, \
		uint16_t ip_checksum, uint16_t tcp_checksum) 
{
   
   build_ip_hdr_(ip_id, ip_ttl, ip_src, ip_dst);
   
   build_tcp_hdr_(tcp_sp, tcp_dp, tcp_seq, tcp_ack, tcp_win, tcp_flag);
   
   if(tcp_mss > 0) 
   {
      //insert tcp mss option
      uint8_t tcp_opt[TCPOLEN_MAXSEG];		//4 bytes
      memset(tcp_opt, 0, TCPOLEN_MAXSEG);
      tcp_opt[0] = TCPOPT_MAXSEG;
      tcp_opt[1] = TCPOLEN_MAXSEG;
      *(uint16_t *)(tcp_opt+2) = htons(tcp_mss);
      build_tcp_option_(tcp_opt, TCPOLEN_MAXSEG);
   }
   
   if(tcp_tsval > 0 || tcp_tsecr > 0) 
   {
      //insert tcp timestamp option
      uint8_t tcp_opt[TCPOLEN_TSTAMP_APPA];	//12 bytes
      memset(tcp_opt, 0, TCPOLEN_TSTAMP_APPA);
      tcp_opt[0] = tcp_opt[1] = TCPOPT_NOP;
      tcp_opt[2] = TCPOPT_TIMESTAMP;
      tcp_opt[3] = TCPOLEN_TIMESTAMP;
      *(uint32_t *)(tcp_opt+4) = htonl(tcp_tsval);
      *(uint32_t *)(tcp_opt+8) = htonl(tcp_tsecr);
      build_tcp_option_(tcp_opt, TCPOLEN_TSTAMP_APPA);
   }
   
   if(tcp_payload_len > 0)
   {
      uint16_t tmp_len;
      if (tcp_payload_len + get_ip_len() > MAX_LEN)
      {
	 tmp_len = MAX_LEN - get_ip_len();
      }
      else
      {
	 tmp_len = tcp_payload_len;
      }
      build_payload_(tcp_payload, tmp_len);
   }
   
   if(tcp_checksum > 0)
   {
      tcp_hdr->check = tcp_checksum;
   }
   else
   {
      do_checksum_(IPPROTO_TCP);
   }
   
   if(ip_checksum > 0)
   {
      ip_hdr->ip_sum=ip_checksum;
   }
   else
   {
      do_checksum_(IPPROTO_IP);
   }
   
   return;
}

/* build an ICMP packet */
void Packet::build_icmp_pkt(uint32_t ip_src, uint32_t ip_dst, uint16_t ip_id, uint8_t ip_ttl, \
		uint8_t icmp_type, uint8_t icmp_code, uint16_t id, uint16_t seq, \
		uint8_t *icmp_payload, uint16_t icmp_payload_len, uint16_t ip_checksum, \
		uint16_t icmp_checksum) 
{
   
   build_ip_hdr_(ip_id, ip_ttl, ip_src, ip_dst);
   
   build_icmp_hdr_(icmp_type, icmp_code, id, seq);

   if(icmp_payload_len>0)
   {
      build_payload_(icmp_payload, icmp_payload_len);
   }

   if(icmp_checksum>0)
   {
      icmp_hdr->checksum = icmp_checksum;
   }
   else
   {
      do_checksum_(IPPROTO_ICMP);
   }

   if(ip_checksum>0)
   {
      ip_hdr->ip_sum=ip_checksum;
   }
   else
   {
      do_checksum_(IPPROTO_IP);
   }
   
   return;
}

uint16_t Packet::get_icmp_payload_len() 
{ 
   return get_ip_len()-get_ip_hdr_len()-ICMP_H; 
}

uint16_t Packet::get_icmp_time_exceed_ipid() 
{
   if(!is_icmp()) 
   {
      return 0;
   }

   if(icmp_hdr->type != 11 || icmp_hdr->code != 0 || get_icmp_payload_len()==0) 
   {
      return 0;
   }

   struct ip* ip_hdr = (struct ip*)(payload);
   return ntohs(ip_hdr->ip_id);
}

uint8_t* Packet::get_tcp_opt(uint8_t opt) 
{
   uint16_t len;
   uint8_t* tcp_opt;
   uint8_t* p;
   
   if(!is_tcp()) 
   {
      return NULL;
   }
   
   if((len=get_tcp_opt_len()) <= 0) 
   {
      return NULL;
   }

   p = tcp_opt = (uint8_t*)tcp_hdr + TCP_H;
   while (p<(tcp_opt+len)) 
   {
      if(*p==opt) 
      {
	 return p+2;
      }
      switch(*p) 
      {
	 case TCPOPT_EOL:
	 case TCPOPT_NOP:
	    p++;
	    break;
	 default:
	    p+=*(p+1);
	    break;
      }
   }
   return NULL;
}

uint16_t Packet::get_tcp_mss() 
{
   uint8_t* tcp_mss = get_tcp_opt(TCPOPT_MAXSEG);
   return tcp_mss ? ntohs(*(uint16_t *)tcp_mss) : 0;
}

void Packet::get_tcp_ts(uint32_t* tsval, uint32_t* tsecr) 
{
   uint8_t* tcp_ts = get_tcp_opt(TCPOPT_TIMESTAMP);
   if(tcp_ts)
   {
      *tsval=ntohl(*(uint32_t *)tcp_ts);
      *tsecr=ntohl(*(uint32_t *)(tcp_ts+4));
   }
   else
   {
      *tsval=*tsecr=0;
   }
   return;
}

void Packet::print()
{
   uint32_t tsval, tsecr;
   char sip_str[INET_ADDRSTRLEN];
   char dip_str[INET_ADDRSTRLEN];

   inet_ntop(AF_INET, &ip_hdr->ip_src.s_addr, sip_str, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &ip_hdr->ip_dst.s_addr, dip_str, INET_ADDRSTRLEN);

   get_tcp_ts(&tsval,&tsecr);
   switch(get_ip_protocol()) 
   {
      case IPPROTO_TCP:
	 std::cout << "TCP packet: "
	      << "[" << get_ts().tv_sec << "." << std::setw(9) << std::setfill('0') << get_ts().tv_nsec << "] ["
	      << sip_str << ":" << get_tcp_sport() << "->"
	      << dip_str << ":" << get_tcp_dport() << "] "
	      << "[S:" << get_tcp_seq() << "] "
	      << "[A:" << get_tcp_ack() << "] "
	      << "[L:" << get_tcp_payload_len() << "] "
	      << "[M:" << get_tcp_mss() << "] "
	      << "[TV:" << tsval << "] "
	      << "[TE:" << tsecr << "]"
	      << std::endl << std::flush;
	 break;
      case IPPROTO_ICMP:
	 std::cout << "ICMP packet: ["
	      << sip_str << "->"
	      << dip_str << "] " 
	      << "[TTL:" << get_ip_ttl() << "]"
	      << std::endl << std::flush;
	 break;
      default:
	 std::cout << "Unknown packet!" << std::endl << std::flush;
	 break;
   }
}



