/*
 * AsyncBuffer provides an async buffer to store captured packets 
 * Last modified for release!
*/

#include <time.h>

#include "common.h"
#include "asyncBuffer.h"
#include "log.h"

extern Log* logger;

/* constructor */
AsyncBuffer::AsyncBuffer()
{
   pthread_mutex_init(&access_lock, NULL);
   pthread_cond_init(&empty_flag, NULL);
}

/* destructor */
AsyncBuffer::~AsyncBuffer()
{
   pthread_cond_broadcast(&empty_flag);
   pthread_mutex_unlock(&access_lock);
   pthread_mutex_destroy(&access_lock);
   pthread_cond_destroy(&empty_flag);

   while(!packet_queue.empty())
   {
      Packet* pkt = packet_queue.front();
      packet_queue.pop();
      delete pkt;
   }
}


/* insert a Packet* into the asyncBuffer */
int AsyncBuffer::push(Packet* pkt)
{
   pthread_mutex_lock(&access_lock);
   packet_queue.push(pkt);
   // notify it is not empty from now on!
   pthread_cond_signal(&empty_flag);
   pthread_mutex_unlock(&access_lock);
   return 0;
}

/* extract a Packet* from the asyncBuffer */
Packet* AsyncBuffer::pop(double timeout)
{
   struct timespec to;
   clock_gettime(CLOCK_REALTIME, &to);
   ts_add(&to, double2ts(timeout)) ;
   
   pthread_mutex_lock(&access_lock);
   if (packet_queue.empty())
   {
      //wait the queue is not empty until timeout
      if(pthread_cond_timedwait(&empty_flag, &access_lock, &to)==ETIMEDOUT) 
      {
	 pthread_mutex_unlock(&access_lock);
	 return NULL;
      }
   }
   Packet* pkt = packet_queue.front();
   packet_queue.pop();
   pthread_mutex_unlock(&access_lock);
   return pkt;
}

