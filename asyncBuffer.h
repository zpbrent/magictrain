/*
 * asyncBuffer.h
 * Header file for asyncBuffer program
 * Last modified for release!
*/

#ifndef __asyncBuffer_h__
#define __asyncBuffer_h__

#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>

#include <iostream>       // std::cout
#include <queue>          // std::queue

#include "packet.h"

class AsyncBuffer
{
   private:
      std::queue<Packet*> packet_queue;
      pthread_mutex_t access_lock;
      pthread_cond_t empty_flag;

   public:
      AsyncBuffer();
      ~AsyncBuffer();


      // operator
      int push(Packet* pkt);
      Packet* pop(double timeout);

};

#endif

