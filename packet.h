/*
 * packet.h
 * Header file for packet program
*/

#ifndef __packet_h__
#define __packet_h__

#define CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

// definition for TCP
#define TCP_H            0x14    /* TCP header:          20 bytes */
#define TH_FIN           0x01
#define TH_SYN           0x02
#define TH_RST           0x04
#define TH_PUSH          0x08
#define TH_ACK           0x10
#define TH_URG           0x20

// definition for IP
#define IPVER            0x04    /* IP version 4                  */
#define IPV4_H           0x14    /* IPv4 header:         20 bytes */

// definition for ICMP
#define ICMP_H           0x08    /* ICMP header:         8 bytes  */

// packet's maximum length
#define MAX_LEN 1500

// Packet's buf_ size
#define BUF_SIZE 2000

class Packet
{
   private:
      uint8_t buf_[BUF_SIZE];	// Packet buffer, no more than 65535 bytes
      uint16_t len_;		// Packet length

      struct timespec ts;       // the timestamp of the packet
      struct ip* ip_hdr;        // ip header 
      struct tcphdr* tcp_hdr;   // tcp header
      struct icmphdr* icmp_hdr; // icmp header
      uint8_t* payload;		// payload pointer to TCP or ICMP content

   public:
      Packet(const uint8_t *b, uint16_t len, struct timespec t);
      Packet();
      ~Packet();
      
      int in_cksum_(uint16_t *addr, int len);
      int do_checksum_(int protocol);
      bool is_tcp(); 
      bool is_icmp();
      bool is_icmp_ttl_exceeded();
      bool is_tcp_fin();
      bool is_tcp_syn(); 
      bool is_tcp_rst();
      bool is_tcp_psh();
      bool is_tcp_ack();
      bool is_tcp_urg();
      struct timespec get_ts();
      struct ip* get_ip_hdr();
      uint16_t get_ip_len();
      uint16_t get_ip_hdr_len();
      uint16_t get_ip_payload_len();
      uint8_t* get_ip_pkt_buf();
      uint32_t get_sip();
      uint32_t get_dip();
      uint8_t get_ip_ttl();
      uint8_t get_ip_protocol();
      uint16_t get_ip_id();
      uint16_t get_tcp_payload_len();
      struct tcphdr* get_tcp_hdr();
      uint16_t get_tcp_hdr_len();
      uint16_t get_tcp_sport_raw();
      uint16_t get_tcp_sport();
      uint16_t get_tcp_dport_raw();
      uint16_t get_tcp_dport();
      uint32_t get_tcp_seq();
      uint32_t get_tcp_ack();
      uint16_t get_tcp_win();
      uint16_t get_tcp_opt_len();
      uint8_t* get_tcp_opt();
      void reset();
      void build_pkt(const uint8_t *b, uint16_t len);
      void set_ts(struct timespec t);
      void set_payload(uint8_t* p);
      void reset_ip_hdr_checksum();
      void update_ip_len_(uint16_t l);
      void build_ip_hdr_(uint16_t id, uint8_t ttl, uint32_t src, uint32_t dst);
      void update_tcp_flag_(uint8_t flag);
      void update_tcp_off_(uint16_t l);
      void build_tcp_hdr_(uint16_t sp, uint16_t dp, uint32_t seq, \
			  uint32_t ack, uint16_t win, uint8_t flag); 
      void build_tcp_option_(uint8_t *opt, uint16_t len);
      void build_icmp_hdr_(uint8_t type, uint8_t code, uint16_t id, uint16_t seq);
      void build_payload_(uint8_t *p, uint16_t len);
      void build_tcp_pkt(uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_sp, uint16_t tcp_dp, \
			 uint32_t tcp_seq, uint32_t tcp_ack, uint16_t ip_id, uint8_t ip_ttl, \
			 uint16_t tcp_win, uint8_t tcp_flag, uint16_t tcp_mss, uint32_t tcp_tsval, \
			 uint32_t tcp_tsecr, uint8_t *tcp_payload, uint16_t tcp_payload_len, \
			 uint16_t ip_checksum, uint16_t tcp_checksum);
      void build_icmp_pkt(uint32_t ip_src, uint32_t ip_dst, uint16_t ip_id, uint8_t ip_ttl, \
			   uint8_t icmp_type, uint8_t icmp_code, uint16_t id, uint16_t seq, \
			   uint8_t *icmp_payload, uint16_t icmp_payload_len, uint16_t ip_checksum, \
			   uint16_t icmp_checksum); 
      uint16_t get_icmp_payload_len();
      uint16_t get_icmp_time_exceed_ipid();
      uint8_t* get_tcp_opt(uint8_t opt);
      uint16_t get_tcp_mss();
      void get_tcp_ts(uint32_t* tsval, uint32_t* tsecr);
      void print();


};
#endif

