/*
 * trainEngine class is the core of magic train
 * Last modified for release!
*/

#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "trainEngine.h"
#include "log.h"
#include "asyncBuffer.h"

extern Log* logger;
extern AsyncBuffer* globalBuf; 

/* Constructor */
TrainEngine::TrainEngine(Config* conf, TranHandler* thandler)
{
   conf_ = conf;
   th_ = thandler;
   pkt_ = NULL;
   request_ = NULL;
   request_cnt_ = 0;
   response_ = NULL;
   response_cnt_ = 0;
   payload_ = NULL;
   non_exist_cnt = 0;
   craft_payload(conf_->get_payload_len());
   for (int i=0; i<CAPNUM; i++)
   {
      minDelay[i]=10000; // set 10000 seconds, it should be lerge enough for possible delays
   }
}

/* Destructor */
TrainEngine::~TrainEngine()
{
   if (payload_)
   {
      free(payload_);
   }
   cleanup();
}

void TrainEngine::cleanup()
{
   if (pkt_)
   {
      delete[] pkt_;
   }
   if (request_)
   {
      for (int i=0; i<trainSize; i++)
      {
	 if (request_[i])
	 {
	    delete request_[i];
	 }
      }
      delete[] request_;
   }
   if (response_)
   {
      for (int i=0; i<trainSize; i++)
      {
	 if (response_[i])
	 {
	    delete response_[i];
	 }
      }
      delete[] response_;
   }
   request_cnt_ = 0;
   response_cnt_ = 0;
   non_exist_cnt = 0;
}

/* craft payload to train's packet */
void TrainEngine::craft_payload(int len)
{
   len_=len;
   payload_ = (uint8_t*)malloc(len_);
   memset(payload_, 0, len_);
   sprintf((char*)payload_, 
	    "GET / HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "User-Agent: Mozilla/4.0\r\n"
	    "Accept: */*\r\n"
	    "Connection: keep-alive\r\n\r\n", 
	    conf_->get_dst_ip());
}


/* generate a TCP SYN packet */
Packet* TrainEngine::gen_tcp_syn(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   Packet* p = new Packet();
   p->build_tcp_pkt(
	 conf_->get_sip(),	// source IP
	 conf_->get_dip(),	// destination IP
	 tcp_sp,		// source port
	 conf_->get_dst_port(),	// destination port
	 tcp_seq,		// sequence number
	 0,			// acknowledgement number
	 10010,			// ipid
	 TTL,			// ttl
	 2000,			// advertising window
	 TH_SYN,		// TCP flag
	 1200,			// TCP MSS
	 tcp_timeval,		// tcp_tsval
	 0,			// tcp_tsecr
	 NULL,			// TCP payload
	 0,			// TCP payload length
	 0,			// IP checksum
	 0);			// TCP checksum
   return p;
}

/* generate a TCP RST packet */
Packet* TrainEngine::gen_tcp_rst(uint16_t tcp_sp)
{
   Packet* p = new Packet();
   p->build_tcp_pkt(
	 conf_->get_sip(),	// source IP
	 conf_->get_dip(),	// destination IP
	 tcp_sp,		// source port
	 conf_->get_dst_port(),	// destination port
	 next_seq,		// sequence number
	 next_ack,		// acknowledgement number
	 10010,			// ipid
	 TTL,			// ttl
	 0,			// advertising window
	 TH_RST,		// TCP flag
	 0,			// TCP MSS
	 0,			// tcp_tsval
	 0,			// tcp_tsecr
	 NULL,			// TCP payload
	 0,			// TCP payload length
	 0,			// IP checksum
	 0);			// TCP checksum
   return p;

}

/* generate a TCP ACK packet */
Packet* TrainEngine::gen_tcp_ack(uint16_t tcp_sp, uint32_t tcp_timeval, uint32_t tcp_timeecr)
{
   Packet* p = new Packet();
   p->build_tcp_pkt(
	 conf_->get_sip(),	// source IP
	 conf_->get_dip(),	// destination IP
	 tcp_sp,		// source port
	 conf_->get_dst_port(),	// destination port
	 next_seq,		// sequence number
	 next_ack,		// acknowledgement number
	 10010,			// ipid
	 TTL,			// ttl
	 0,			// advertising window
	 TH_RST,		// TCP flag
	 0,			// TCP MSS
	 tcp_timeval,		// tcp_tsval
	 tcp_timeecr,		// tcp_tsecr
	 NULL,			// TCP payload
	 0,			// TCP payload length
	 0,			// IP checksum
	 0);			// TCP checksum
   return p;

}
/* open a TCP flow for TIME_DATA train */
int TrainEngine::tcp_flow_open(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   Packet* ps = gen_tcp_syn(tcp_sp, tcp_seq, tcp_timeval); // for sending packet
   Packet* pr = NULL; // for received packet
   int retry = 0;
   uint32_t tsval, tsecr;
   
   th_->th_send_packet(ps); // send SYN
   base_timestamp = tcp_timeval;
   trainType = TIME_DATA;

   while (true)
   {
      if ((pr = globalBuf->pop(TIMEOUT)) != NULL)
      {
	 // whether pr is a TCP SYN+ACK in the flow
	 if (pr->is_tcp() && pr->get_tcp_dport() == tcp_sp && pr->is_tcp_syn() && pr->is_tcp_ack())
	 {
	    delete ps;
	    next_seq = pr->get_tcp_ack();
	    next_ack = pr->get_tcp_seq() + 1;
	    pr->get_tcp_ts(&tsval, &tsecr);
	    //ps = gen_tcp_ack(tcp_sp, tcp_timeval + 1, tsval);
	    //th_->th_send_packet(ps); // send ACK
	    //delete ps;
	    if (tsecr == tcp_timeval)
	    {
	       logger->PrintLog("TIME_DATA: Supported! TCP timestamp is [%lu -> %lu]\n", tcp_timeval, tsecr);
	       delete pr;
	       return 0;
	    }
	    else
	    {
	       logger->PrintLog("TIME_DATA: Unsupported! TCP timestamp is [%lu -> %lu]\n", tcp_timeval, tsecr);
	       delete pr;
	       return -1;
	    }
	 }
	 else
	 {
	    delete pr;
	    continue;
	 }
      }
      else // time out
      {
	 if (retry++ < RETRY_MAX)
	 {
	    th_->th_send_packet(ps); // send SYN again
	    continue;
	 }
	 else
	 {
	    logger->PrintLog("TIME_DATA: TCP flow cannot be open!\n");
	    delete ps;
	    return -2;
	 }
      }
   }
}

/* close a TCP flow that is used by TIME_DATA train */
void TrainEngine::tcp_flow_close(uint16_t tcp_sp)
{
   Packet* p = gen_tcp_rst(tcp_sp);

   for (int i=0; i<RETRY_MAX; i++)
   {
      th_->th_send_packet(p); // send RST
   }
   delete p;
}

/* generate an In-flow TCP Time Data packet train (trainType is TIME_DATA) */
void TrainEngine::gen_tcp_time_data(int train_size, uint16_t tcp_sp, uint32_t tcp_timeval)
{
   base_timestamp = tcp_timeval;
   trainType = TIME_DATA;
   trainSize = train_size;

   pkt_ = new Packet[train_size];
   for (int i=0; i<train_size; i++)
   {
      pkt_[i].build_tcp_pkt(
	    conf_->get_sip(),		// source IP
	    conf_->get_dip(),		// destination IP
	    tcp_sp,			// source port
	    conf_->get_dst_port(),	// destination port
	    next_seq,			// sequence number
	    next_ack,			// acknowledgement number
	    10010,			// ipid
	    TTL,			// ttl
	    0,				// advertising window
	    TH_ACK,			// TCP flag
	    0,				// TCP MSS
	    tcp_timeval + i,		// tcp_tsval
	    0,				// tcp_tsecr
	    payload_,			// TCP payload
	    len_,			// TCP payload length
	    0,				// IP checksum
	    0);				// TCP checksum
      //next_seq = next_seq + pkt_[i].get_tcp_payload_len();
      next_seq++;
   }
}

/* generate an Out-of-flow TCP Data packet train (trainType is OF_DATA) */
void TrainEngine::gen_tcp_of_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq)
{
   base_port = tcp_sp;
   trainType = OF_DATA;
   trainSize = train_size;

   pkt_ = new Packet[train_size];
   for (int i=0; i<train_size; i++)
   {
      pkt_[i].build_tcp_pkt(
	    conf_->get_sip(),		// source IP
	    conf_->get_dip(),		// destination IP
	    tcp_sp + i,			// source port
	    conf_->get_dst_port(),	// destination port
	    tcp_seq,			// sequence number
	    0,				// acknowledgement number
	    10010,			// ipid
	    TTL,			// ttl
	    2000,			// advertising window
	    TH_ACK,			// TCP flag
	    0,				// TCP MSS
	    0,				// tcp_tsval
	    0,				// tcp_tsecr
	    payload_,			// TCP payload
	    len_,			// TCP payload length
	    0,				// IP checksum
	    0);				// TCP checksum
   }
}

/* generate an Out-of-flow TCP SYN data packet train (trainType is SYN_DATA) */
void TrainEngine::gen_tcp_syn_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq)
{
   base_seq = tcp_seq;
   trainType = SYN_DATA;
   trainSize = train_size;

   pkt_ = new Packet[train_size];
   for (int i=0; i<train_size; i++)
   {
      pkt_[i].build_tcp_pkt(
	    conf_->get_sip(),		// source IP
	    conf_->get_dip(),		// destination IP
	    tcp_sp,			// source port
	    conf_->get_dst_port(),	// destination port
	    tcp_seq + i,		// sequence number
	    0,				// acknowledgement number
	    10010,			// ipid
	    TTL,			// ttl
	    2000,			// advertising window
	    TH_SYN,			// TCP flag
	    1200,			// TCP MSS
	    300,			// tcp_tsval
	    0,				// tcp_tsecr
	    payload_,			// TCP payload
	    len_,			// TCP payload length
	    0,				// IP checksum
	    0);				// TCP checksum
   }

   base_ack = base_seq + pkt_[0].get_tcp_payload_len();

}

/* send magic train */
void TrainEngine::send_train()
{
   struct timeval delay;
   delay.tv_sec = 0;
   delay.tv_usec = 0;
   if (pkt_)
   {
      for (int i=0; i<trainSize; i++)
      {
	 th_->th_send_packet(&pkt_[i]);
	 srand(time(NULL));
	 //delay.tv_usec = (rand()%50) * 1000; // for 100Kbit/s 
	 //delay.tv_usec = (rand()%5) * 1000; // for 1Mbit/s
	 select(0, NULL, NULL, NULL, &delay);
      }
      delete[] pkt_;
      pkt_ = NULL;
   }
   else
   {
      logger->PrintErr("[%s:%d] no magic train can be sent!!!\n", __FILE__, __LINE__);
   }
}

/* calculate an index of a captured packet */
int TrainEngine::make_index(Packet* p)
{
   int index;
   uint32_t tsval, tsecr;
   // if the train is TIME_DATA
   if (trainType == TIME_DATA)
   {
      p->get_tcp_ts(&tsval, &tsecr);
      if (check_dir(p) == 0)
      {
	 if (p->is_tcp_rst())
	 {
	    // system sending RST packet
	    logger->PrintDebug("[%s:%d] System sending a packet!\n", __FILE__, __LINE__);
	    if (conf_->get_debug())
	    {
	       p->print();
	    }
	    return -2;
	 }
	 index = tsval - base_timestamp;
      }
      else if (check_dir(p) == 1)
      {
	 index = tsecr - base_timestamp;
      }
      else
      {
	 // impossible packet
	 logger->PrintDebug("[%s:%d] Received an impossible packet!\n", __FILE__, __LINE__);
	 if (conf_->get_debug())
	 {
	    p->print();
	 }
	 return -2;
      }
   }
   // else if the train is OF_DATA
   else if (trainType == OF_DATA)
   {
      if (check_dir(p) == 0)
      {
	 if (p->is_tcp_rst())
	 {
	    // system sending RST packet
	    logger->PrintDebug("[%s:%d] System sending a packet!\n", __FILE__, __LINE__);
	    if (conf_->get_debug())
	    {
	       p->print();
	    }
	    return -2;
	 }
	 index = p->get_tcp_sport() - base_port;
      }
      else if (check_dir(p) == 1)
      {
	 index = p->get_tcp_dport() - base_port;
      }
      else
      {
	 // impossible packet
	 logger->PrintDebug("[%s:%d] Received an impossible packet!\n", __FILE__, __LINE__);
	 if (conf_->get_debug())
	 {
	    p->print();
	 }
	 return -2;
      }
   }
   // if the train is SYN_DATA
   else
   {
      if (check_dir(p) == 0)
      {
	 if (p->is_tcp_rst())
	 {
	    // system sending RST packet
	    logger->PrintDebug("[%s:%d] System sending a packet!\n", __FILE__, __LINE__);
	    if (conf_->get_debug())
	    {
	       p->print();
	    }
	    return -2;
	 }
	 index = p->get_tcp_seq() - base_seq;
      }
      else if (check_dir(p) == 1)
      {
	 // first SYN+DATA triggers a SYN+ACK without echoing the data
	 if (p->is_tcp_syn())
	 {
	    index = p->get_tcp_ack() - base_seq - 1;
	 }
	 // next SYN+DATA triggers a RST+ACK that echos the data
	 else if (p->is_tcp_rst())
	 {
	    index = p->get_tcp_ack() - base_ack - 1;
	 }
	 else
	 {
	    // impossible packet
	    logger->PrintDebug("[%s:%d] Received an impossible packet!\n", __FILE__, __LINE__);
	    if (conf_->get_debug())
	    {
	       p->print();
	    }
	    return -2;
	 }
      }
      else
      {
	 // impossible packet
	 logger->PrintDebug("[%s:%d] Received an impossible packet!\n", __FILE__, __LINE__);
	 if (conf_->get_debug())
	 {
	    p->print();
	 }
	 return -2;
      }
   }

   if (index >= 0 && index < trainSize)
   {
      logger->PrintDebug("[%s:%d] Index is %d\n", __FILE__, __LINE__, index);
      if (conf_->get_debug())
      {
	 p->print();
      }
      return index;
   }
   else if (index < -50 || index > trainSize + 50)
   {
      // non-existent packet
      logger->PrintDebug("[%s:%d] Received an non-existent packet! Index is %d\n", __FILE__, __LINE__, index);
      if (conf_->get_debug())
      {
         p->print();
      }
      return -1;
   }
   else
   {
      // impossible packet
      logger->PrintDebug("[%s:%d] Received an impossible packet!\n", __FILE__, __LINE__);
      if (conf_->get_debug())
      {
	 p->print();
      }
      return -2;
   }
}

/* link response packets to request packets */
void TrainEngine::linking()
{
   Packet* p = NULL;
   int index;

   request_ = new Packet*[trainSize];
   response_ = new Packet*[trainSize];

   for (int i=0; i<trainSize; i++)
   {
      request_[i] = NULL;
      response_[i] = NULL;
   }
   
   while ((p = globalBuf->pop(TIMEOUT)) != NULL)
   {
      index = make_index(p);
      if (index >= 0 && index < trainSize)
      {
	 if (check_dir(p) == 0)
	 {
	    if (!request_[index])
	    {
	       request_[index] = p;
	       request_cnt_++;
	    }
	    else
	    {
	       logger->PrintDebug("[%s:%d] Duplicated request packets!\n", __FILE__, __LINE__);
	       if (conf_->get_debug())
	       {
		  p->print();
	       }
	    }
	 }
	 else if (check_dir(p) == 1)
	 {
	    if (!response_[index])
	    {
	       response_[index] = p;
	       response_cnt_++;
	    }
	    else
	    {
	       logger->PrintDebug("[%s:%d] Duplicated response packets!\n", __FILE__, __LINE__);
	       if (conf_->get_debug())
	       {
		  p->print();
	       }
	    }
	 }
      }
      else if (index == -1)
      {
	 non_exist_cnt++;
	 delete p;
      }
      else
      {
	 delete p;
      }
   }

   // debug infomation
   if (conf_->get_debug())
   {
      for (int i=0; i<trainSize; i++)
      {
	 if (request_[i])
	 {
	    request_[i]->print();
	 }
	 if (response_[i])
	 {
	    response_[i]->print();
	 }
	 std::cout << std::endl;
      }
   }
}

/* check a packet's direction, 0 for request packet, and 1 for response packet, but -1 is impossible */
int TrainEngine::check_dir(Packet* p)
{
   if (conf_->get_dip() == p->get_dip() && conf_->get_dst_port() == p->get_tcp_dport())
   {
      return 0;
   }
   else if (conf_->get_dip() == p->get_sip() && conf_->get_dst_port() == p->get_tcp_sport())
   {
      return 1;
   }
   else
   {
      logger->PrintErr("[%s:%d] Impossible packet direction!!!\n", __FILE__, __LINE__);
      return -1;
   }
}

/* report bandwidth and t1 */
void TrainEngine::reporting()
{
   int s = 0, e = 0, num = 0;
   struct timespec tmp;
   double min;
   int minIndex;
   Packet *start[2], *end[2]; // start and end request and response packets
   start[0] = NULL;
   start[1] = NULL;
   end[0] = NULL;
   end[1] = NULL;
   if (!request_ || !response_)
   {
      logger->PrintDebug("No train data so no report!\n");
      return;
   }

   for (int i=0; i < trainSize; i++)
   {
      // find the first packet
      if (request_[i] && response_[i])
      {
	 s = i;
	 break;
      }
   }
   for (int i=trainSize-1; i >= 0; i--)
   {
      // find the last packet
      if (request_[i] && response_[i])
      {
	 e = i;
	 break;
      }
   }
   for (int i=s; i<=e; i++)
   {
      // find how many packets between start and end
      if (request_[i] && response_[i])
      {
	 if (start[0]==NULL)
	 {
	    start[0] = request_[i];
	    start[1] = response_[i];
	    end[0] = request_[i];
	    end[1] = response_[i];
	 }
	 else
	 {
	    if (start[1]->get_ts().tv_sec > response_[i]->get_ts().tv_sec || (start[1]->get_ts().tv_sec == response_[i]->get_ts().tv_sec && start[1]->get_ts().tv_nsec > response_[i]->get_ts().tv_nsec))
	    {
	       start[0] = request_[i];
	       start[1] = response_[i];
	    }
	    if (end[1]->get_ts().tv_sec < response_[i]->get_ts().tv_sec || (end[1]->get_ts().tv_sec == response_[i]->get_ts().tv_sec && end[1]->get_ts().tv_nsec < response_[i]->get_ts().tv_nsec))
	    {
	       end[0] = request_[i];
	       end[1] = response_[i];
	    }
	 }
	 num++;
      }
   }
   num--;

   if (num>0)
   {
      // first packet delay
      tmp = start[1]->get_ts();
      ts_sub(&tmp, start[0]->get_ts());
      t1 = ts2double(tmp);
      logger->PrintLog("t1 is %f sec\n", t1);

      // bandwidth can be calculated
      tmp = end[1]->get_ts();
      ts_sub(&tmp, start[1]->get_ts());
      logger->PrintLog("e-s is %d, num is %d, delta t is %f sec\n", e-s, num, ts2double(tmp));
      //bw = (DEFAULT_MSS*8*(e-s))/ts2double(tmp);
      bw = (DEFAULT_MSS*8*num)/ts2double(tmp);
      logger->PrintLog("bandwidth is %f bps\n", bw);
   }
   // tailed dropNum can be calculated
   dropNum=trainSize-1-e;
   logger->PrintLog("the number of packets dropped at the end is %f\n", dropNum);
   
   // for capacity calculation
   for (int j=0; j < trainSize; j++)
   {
      min = 100000;
      minIndex = -1;
      for (int i=0; i < trainSize; i++)
      {
	 if (response_[i])
	 {
	    if (minIndex == -1 || ts2double(response_[i]->get_ts()) < min)
	    {
	       min = ts2double(response_[i]->get_ts());
	       minIndex = i;
	    }
	 }
      }
      if (minIndex == -1)
      {
	 break;
      }
      else
      {
	 delete response_[minIndex];
	 response_[minIndex] = NULL;
      }
      if (min-ts2double(request_[0]->get_ts()) < minDelay[j])
      {
	 minDelay[j]=min-ts2double(request_[0]->get_ts());
      }
   }
   // minimal delay now
   logger->PrintLog("minimal delay: ");
   for (int i=0; i<CAPNUM; i++)
   {
      if (minDelay[i] != 10000)
      {
	 fprintf(stdout, "m[%d]=%f, ", i, minDelay[i]);
      }
   }
   fprintf(stdout, "\n");
   // dispersion now
   logger->PrintLog("dispersion now: ");
   for (int i=1; i<CAPNUM; i++)
   {
      if (minDelay[i] != 10000)
      {
	 fprintf(stdout, "d[%d]=%f, ", i, minDelay[i]-minDelay[i-1]);
      }
   }
   fprintf(stdout, "\n");
}

/* measure the target prover */
void TrainEngine::measure(int train_type, int train_size, uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   switch(train_type)
   {
      case TIME_DATA:
	 measure_time_data(train_size, tcp_sp, tcp_seq, tcp_timeval);
	 break;	
      case OF_DATA:
	 measure_of_data(train_size, tcp_sp, tcp_seq);
	 break;
      case SYN_DATA:
	 measure_syn_data(train_size, tcp_sp, tcp_seq);
	 break;
      default:
	 measure_time_data(train_size, tcp_sp, tcp_seq, tcp_timeval);
	 break;
   }
}

/* measure the target prover using TIME_DATA train */
void TrainEngine::measure_time_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   tcp_flow_open(tcp_sp, tcp_seq, tcp_timeval);
   if (train_size > MAX_TIME_DATA_LEN)
   {
      gen_tcp_time_data(MAX_TIME_DATA_LEN, tcp_sp, tcp_timeval + 2);
   }
   else
   {
      gen_tcp_time_data(train_size, tcp_sp, tcp_timeval + 2);
   }
   send_train();
   linking();
   logger->PrintLog("[%s:%d] TIME_DATA: %d, %d\n", __FILE__, __LINE__, request_cnt_, response_cnt_);
   tcp_flow_close(tcp_sp);
   reporting();
   cleanup();
}

/* measure the target prover using OF_DATA train */
void TrainEngine::measure_of_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq)
{
   if (train_size > MAX_OF_DATA_LEN)
   {
      gen_tcp_of_data(MAX_OF_DATA_LEN, tcp_sp, tcp_seq);
   }
   else
   {
      gen_tcp_of_data(train_size, tcp_sp, tcp_seq);
   }
   send_train();
   linking();
   logger->PrintLog("[%s:%d] OF_DATA: %d, %d\n", __FILE__, __LINE__, request_cnt_, response_cnt_);
   reporting();
   cleanup();
}

/* measure the target prover using SYN_DATA train */
void TrainEngine::measure_syn_data(int train_size, uint16_t tcp_sp, uint32_t tcp_seq)
{
   if (train_size > MAX_SYN_DATA_LEN)
   {
      gen_tcp_of_data(MAX_SYN_DATA_LEN, tcp_sp, tcp_seq);
   }
   else
   {
      gen_tcp_syn_data(train_size, tcp_sp, tcp_seq);
   }
   send_train();
   linking();
   logger->PrintLog("[%s:%d] SYN_DATA: %d, %d\n", __FILE__, __LINE__, request_cnt_, response_cnt_);
   reporting();
   cleanup();
}


/* test whether the target prover support TIME_DATA train */
void TrainEngine::test_time_data(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   tcp_flow_open(tcp_sp, tcp_seq, tcp_timeval);
   tcp_flow_close(tcp_sp);
   cleanup();
}

/* test whether the target prover support OF_DATA train */
void TrainEngine::test_of_data(uint16_t tcp_sp, uint32_t tcp_seq)
{
   gen_tcp_of_data(3, tcp_sp, tcp_seq);
   send_train();
   linking();
   logger->PrintLog("[%s:%d] OF_DATA: %d, %d\n", __FILE__, __LINE__, request_cnt_, response_cnt_);
   cleanup();
}

/* test whether the target prover support SYN_DATA train */
void TrainEngine::test_syn_data(uint16_t tcp_sp, uint32_t tcp_seq)
{
   gen_tcp_syn_data(3, tcp_sp, tcp_seq);
   send_train();
   linking();
   logger->PrintLog("[%s:%d] SYN_DATA: %d, %d\n", __FILE__, __LINE__, request_cnt_, response_cnt_);
   cleanup();
}

/* test in one call */
void TrainEngine::test(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   test_time_data(tcp_sp, tcp_seq, tcp_timeval);
   test_of_data(tcp_sp, tcp_seq);
   test_syn_data(tcp_sp, tcp_seq);
}

/* RTT estimation */
void TrainEngine::RTT_est(uint16_t tcp_sp, uint32_t tcp_seq, uint32_t tcp_timeval)
{
   // TIME-DATA-TRAIN
   tcp_flow_open(tcp_sp, tcp_seq, tcp_timeval);
   gen_tcp_time_data(1, tcp_sp, tcp_timeval + 2);
   send_train();
   linking();
   tcp_flow_close(tcp_sp);
   reporting();
   cleanup();

   // OF-DATA-TRAIN
   gen_tcp_of_data(1, tcp_sp+1, tcp_seq);
   send_train();
   linking();
   reporting();
   cleanup();
   
   // SYN-DATA-TRAIN
   gen_tcp_syn_data(1, tcp_sp+2, tcp_seq);
   send_train();
   linking();
   reporting();
   cleanup();
}






