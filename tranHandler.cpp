/*
 * tranhandler class for handling packet sending and receiving
 * This is just a template and you should implement your own functions using specific tech
*/

#include "tranHandler.h"
#include "log.h"
#include "asyncBuffer.h"

extern Log* logger;
extern AsyncBuffer* globalBuf;

/* Constructor */
TranHandler::TranHandler()
{
}

/* Destructor */
TranHandler::~TranHandler()
{
}


/* processing the received packets */
void TranHandler::th_process_packet(Packet* pkt)
{
   if (pkt->is_tcp())
   {
      logger->PrintDebug("[%s:%d] received a TCP packet\n", __FILE__, __LINE__);
      globalBuf->push(pkt);
   }
   else if (pkt->is_icmp())
   {
      logger->PrintDebug("[%s:%d] received an ICMP packet\n", __FILE__, __LINE__);
      pkt->print();
      delete pkt;
   }
   else
   {
      logger->PrintDebug("[%s:%d] received an unknown packet\n", __FILE__, __LINE__);
      pkt->print();
      delete pkt;
   }


}


