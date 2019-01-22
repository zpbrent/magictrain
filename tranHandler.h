/*
 * tranHandler.h
 * Header file for transmission handler template program 
 * Last modified for release!
*/

#ifndef __tranTemplate_h__
#define __tranTemplate_h__

#include <netinet/in.h>
#include "packet.h"

#define TTL 254

class TranHandler
{
   private:

   public:
      TranHandler();
      ~TranHandler();

      // handling received packets
      static void th_process_packet(Packet* pkt);

      // interfaces that must be implemented by derived classes
      virtual int th_send_packet(Packet* pkt) = 0;
      virtual int th_start_capture() = 0;
      virtual int th_cleanup() = 0;
};

#endif

