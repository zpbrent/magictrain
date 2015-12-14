/*
 * rawsocketcore.h
 * - Header file for rawsocketcore.cpp
 */

#ifndef __rawsocketcore_h__
#define __rawsocketcore_h__

#include <netinet/in.h>
#include "packet.h"

class RawSocket
{
   private:
      int fd;		//file descriptor for raw socket;
      struct sockaddr_in dst_sin_;
      bool isOpen;


   public:
      RawSocket(uint32_t dip, uint16_t dp, uint16_t sp);
      ~RawSocket();

      int create_socket();
      void del_socket();
      int open(uint32_t dip, uint16_t dp, uint16_t sp);
      void bind_sp(uint16_t sp);
      int send(Packet *p);

};

#endif 

