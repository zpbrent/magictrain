/*
 * pcapcore.h
 * - Header file for pcapcore.cpp
 */

#ifndef __pcapcore_h__
#define __pcapcore_h__

#include <pcap.h>
#include "packet.h"

#define	DLT_LINUX_SLL_LEN	(16)
#define	DLT_EN10MB_LEN		(14)
#define	DLT_IEEE802_LEN		(22)
#define	DLT_NULL_LEN		(4)
#define	DLT_SLIP_LEN		(24)
#define	DLT_PPP_LEN		(24)
#define	DLT_RAW_LEN		(0)

#define PCAP_NETMASK_UNKNOWN	0xffffffff


class Pcap 
{
   private:
      pcap_t *hd; // session handle
      pcap_dumper_t *pd;
      uint16_t dataLinkOffset;
      bool isOpen;
      pthread_t process_thread;
      double last_pcap_time;
      void (*process_packet)(Packet* pkt);

   public:
      Pcap(char *dev, int snaplen, char *src_ip, char *dst_ip, int src_port, int dst_port, char *output_file, void (*p)(Packet* pkt));
      ~Pcap();

      static void* process_thread_func_(void* p_arg);
      static void pcap_next_wrapper_(u_char *pd, const struct pcap_pkthdr* pkthdr, const u_char* packetBuf);
      void pcap_next_(u_char *pd, const struct pcap_pkthdr* pkthdr, const u_char* packetBuf);
      int start_thread();
      void destroy();
      void add_dump(char *file);
      int add_filter(char *src_ip, int src_port, char *dst_ip, int dst_port);
};

#endif

