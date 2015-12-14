/*
 * rawsocketcore.cpp
 * - Pragram for handling raw socket functions 
 */

#include <errno.h>
#include <string.h>
#include <sys/types.h>       // For data types
#include <sys/socket.h>      // For socket(), connect(), send(), and recv()
#include <netdb.h>           // For gethostbyname()
#include <arpa/inet.h>       // For inet_addr()
#include <unistd.h>          // For close()
#include <netinet/in.h>      // For sockaddr_in
#include <ctype.h>	     // For isdigit()
#include "rawSocketCore.h"
#include "log.h"

extern Log* logger;

/* constuctor */
RawSocket::RawSocket(uint32_t dip, uint16_t dp, uint16_t sp)
{
   fd = 0;
   memset(&dst_sin_, 0, sizeof(struct sockaddr_in));
   isOpen = false;

   create_socket();
   open(dip, dp, sp);
}

/* destructor */
RawSocket::~RawSocket()
{
   del_socket();
}

int RawSocket::create_socket() 
{
   if ((fd=socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) 
   {
      logger->PrintErr("[%s:%d] SOCK_RAW allocation failed: %s\n", __FILE__, __LINE__, strerror(errno));
      return -1;
   }
   isOpen = true;
   return 0;
}

void RawSocket::del_socket() 
{
   if(isOpen) 
   {
      ::close(fd);
   }
   isOpen = false;
}

int RawSocket::open(uint32_t dip, uint16_t dp, uint16_t sp)
{
   int n = 1;
   
   del_socket();
   create_socket();
   
   dst_sin_.sin_family = PF_INET;
   dst_sin_.sin_port = htons(dp);
   dst_sin_.sin_addr.s_addr = dip;
   
   bind_sp(sp);
   if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) == -1) 
   {
      logger->PrintErr("[%s:%d] set IP_HDRINCL failed: %s\n", __FILE__, __LINE__, strerror(errno));
      return -1;
   }
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n)) == -1) 
   {
      logger->PrintErr("[%s:%d] set SO_REUSEADDR failed: %s", __FILE__, __LINE__, strerror(errno));
      return -1;
   }
   return 0;
}

void RawSocket::bind_sp(uint16_t sp) 
{
   struct sockaddr_in sin;
   memset((char *)& sin, 0, sizeof(sin));
   sin.sin_port = htons(sp);
   bind(fd, (struct sockaddr *)& sin, sizeof(sin));
}


// send a packet
int RawSocket::send(Packet *p) 
{
   if (!isOpen) 
   {
      logger->PrintErr("[%s:%d] Socket not opened\n", __FILE__, __LINE__);
      return -1;
   }
   // we only send TCP packets in our implementation
   if(p == NULL || !p->is_tcp()) 
   {
      logger->PrintErr("[%s:%d] Socket not understand the packet type\n", __FILE__, __LINE__);
      return -1;
   }

   // Send now!
   int len = sendto(fd, p->get_ip_pkt_buf(), p->get_ip_len(), 0, (struct sockaddr *)&dst_sin_, sizeof(struct sockaddr));
   if (len != p->get_ip_len())
   {
      logger->PrintErr("[%s:%d] Socket send failed. Need to sent %d bytes, but actual send %d bytes.\n", __FILE__, __LINE__, p->get_ip_len(), len);
      return -1;
   }
   // Send successful.
   return 0;
}



