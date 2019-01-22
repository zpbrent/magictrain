/*
 * th_rawpcap.h
 * Header file for RAW socket + pcap transmission program
 * Last modified for release!
*/

#ifndef __th_rawpcap_h__
#define __th_rawpcap_h__

#include "config.h"
#include "tranHandler.h"
#include "rawSocketCore.h"
#include "pcapCore.h"

class TH_RawPcap : public TranHandler
{
   private:
      Pcap* pcap_;	// for receiving packets
      RawSocket* sock_; // for sending packets
      Config* conf_;

   public:
      TH_RawPcap(Config* conf);
      ~TH_RawPcap();

      int launch_iptable_rule();
      int delete_iptable_rule();

      // interfaces inherited from father class TranHandler
      int th_send_packet(Packet* pkt);
      int th_start_capture();
      int th_cleanup();
};

#endif

