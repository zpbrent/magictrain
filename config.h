/*
 * config structure 
 * Last modified for release!
*/

#ifndef __config_h__
#define __config_h__

#include <netinet/in.h>

// packet length pcap captured
#define SNAPLEN 96

// default destination port number is 80, for HTTP
#define HTTP_PORT 80

// default payload size of each packet
#define DEFAULT_MSS 1500

// configuration structure
class Config
{
   private:
      char* src_ip;
      uint32_t sip;
      char* dst_ip;
      uint32_t dip;
      int src_port;
      int dst_port;
      char* dev;		// iface
      int snaplen;	    
      char* output_file;	// output file name
      int payload_len;
      bool debug;
      bool test;
      bool RTT_est;
      bool pp_measure;
      int train_type;
      int round_num;

   public:
      Config();
      ~Config();

      int set_source_iface();
      int set_source_IP(char* ifname);
      int set_dest_IP(char* address);

      void set_default_output_file();

      inline void set_src_ip(char* ip)		{ src_ip = ip; }
      inline void set_sip(uint32_t ip)		{ sip = ip; }
      inline void set_dst_ip(char* ip)		{ dst_ip = ip; }
      inline void set_dip(uint32_t ip)		{ dip = ip; }
      inline void set_src_port(int port)	{ src_port = port; }
      inline void set_dst_port(int port)	{ dst_port = port; }
      inline void set_dev(char* ifname)		{ dev = ifname; }
      inline void set_snaplen(int len)		{ snaplen = len; }
      inline void set_output_file(char* fname)	{ output_file = fname; }
      inline void set_payload_len(int len)	{ payload_len = len; }
      inline void set_debug(bool d)		{ debug = d; }
      inline void set_test(bool te)		{ test = te; }
      inline void set_RTT_est(bool rtt)		{ RTT_est = rtt; }
      inline void set_pp_measure(bool pp)	{ pp_measure = pp; }
      inline void set_train_type(int t)		{ train_type = t; }
      inline void set_round_num(int r)		{ round_num = r; }

      inline char* get_src_ip()		{ return src_ip; }
      inline uint32_t get_sip()		{ return sip; }
      inline char* get_dst_ip()		{ return dst_ip; }
      inline uint32_t get_dip()		{ return dip; }
      inline int get_src_port()		{ return src_port; }
      inline int get_dst_port()		{ return dst_port; }
      inline char* get_dev()		{ return dev; }
      inline int get_snaplen()		{ return snaplen; }
      inline char* get_output_file()	{ return output_file; }
      inline int get_payload_len()	{ return payload_len; }
      inline bool get_debug()		{ return debug; }
      inline bool is_test()		{ return test; }
      inline bool is_RTT_est()		{ return RTT_est; }
      inline bool is_pp_measure()	{ return pp_measure; }
      inline int get_train_type()	{ return train_type; }
      inline int get_round_num()	{ return round_num; }
};

#endif

