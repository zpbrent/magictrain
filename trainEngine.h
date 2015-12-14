/*
 * trainengine.h
 * Header file for magic train engine program
*/

#ifndef __trainengine_h__
#define __trainengine_h__

#include <netinet/in.h>
#include "packet.h"
#include "config.h"
#include "tranHandler.h"

// define train type
// TIME_DATA is for in-flow data packet which can be linked through TCP timestamp
// TIME_DATA will trigger an ACK with TCP timestamp
// TIME_DATA needs to use request packet's TCP_TSVAL and and response packet's TCP_TSECR for linking 
#define TIME_DATA 0
// OF_DATA is for our-of-flow data packet (i.e., tcp data packet whose flow does not exist)
// OF_DATA will trigger a pure RST
// OF_DATA needs to use source port to link request with response
#define OF_DATA 1 
// SYN_DATA is for syn packet with data
// SYN_DATA will trigger a RST+ACK or SYN+ACK
// SYN_DATA can use sequence number to link request with response
#define SYN_DATA 2

#define TIMEOUT 2.0
#define RETRY_MAX 3

#define MAX_TIME_DATA_LEN 50
#define MAX_OF_DATA_LEN 100
#define MAX_SYN_DATA_LEN 100

#define CAPNUM 20

class TrainEngine
{
   private:
      Config* conf_;
      TranHandler* th_;
      Packet* pkt_; // RAW socket use it
      Packet** request_; // pcap captured request packets
      int request_cnt_;
      Packet** response_; // pcap captured response packets
      int response_cnt_;
      uint8_t* payload_;
      int len_;

      uint32_t base_timestamp; // used by TIME_DATA train for linking
      uint32_t next_seq; // used by TIME_DATA train to keep a TCP flow
      uint32_t next_ack; // used by TIME_DATA train to keep a TCP flow
      
      int base_port; // used by OF_DATA train for linking
      
      uint32_t base_seq; // used by SYN_DATA train for linking
      uint32_t base_ack; // used by SYN_DATA train for linking
      
      int trainSize; // how long of the train
      int trainType; // 0 for OF_DATA and 1 for SYN_DATA

      int non_exist_cnt; // how many non existent response, if >0, a priori rush attack is possible

      double t1; // RTT of the first packet
      double bw; // bandwidth estimation
      double dropNum; // how many packets dropped at the end of a train

      double minDelay[CAPNUM]; // minimal delay of each measurement packet, used for capacity measurement, we only interests the first CAPNUM minimal delay
      

   public:
      TrainEngine(Config* conf, TranHandler* thandler);
      ~TrainEngine();

      void craft_payload(int len);

      void measure(int train_type, int train_size, uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      void measure_time_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      void measure_of_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq);
      void measure_syn_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq);
      void reporting();

      void test(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      void test_time_data(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      void test_of_data(uint16_t tcp_sp, uint32_t tcp_seq);
      void test_syn_data(uint16_t tcp_sp, uint32_t tcp_seq);

      void RTT_est(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);

      void send_train();

      int tcp_flow_open(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      void tcp_flow_close(uint16_t tcp_sp);
      Packet* gen_tcp_syn(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval);
      Packet* gen_tcp_rst(uint16_t tcp_sp);
      Packet* gen_tcp_ack(uint16_t tcp_sp, uint32_t tcp_timeval, uint32_t tcp_timeecr);

      void gen_tcp_time_data(int train_size, uint16_t tcp_sp, uint32_t tcp_timeval); 
      void gen_tcp_of_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq);
      void gen_tcp_syn_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq);

      void linking();
      int make_index(Packet* p); // calculate an index of a packet
      int check_dir(Packet* p); // check a packet's direction

      inline double get_t1()	    { return t1; }
      inline double get_bw()	    { return bw; }
      inline double get_dropNum()   { return dropNum; }
      inline double get_minDelay(int i)   { return minDelay[i]; }
      inline double get_capacity(int i)   { return (DEFAULT_MSS*8)/(minDelay[i]-minDelay[i-1]); }

      void cleanup();
};

#endif

