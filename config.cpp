// Last modified for release!

#include <stdlib.h>
#include <ifaddrs.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include "config.h"
#include "log.h"

extern Log* logger;

/* Constructor */
Config::Config()
{
   // init dev, src_ip and sip
   set_source_iface();

   dst_ip = NULL;
   dip = 0;
   src_port = 25500;
   dst_port = 0;
   snaplen = SNAPLEN;
   output_file = NULL;
   payload_len = DEFAULT_MSS;
   debug = false;
   test = false;
   RTT_est = false;
   pp_measure = false;
   train_type = 0;
   round_num = 3;
}

/* Destructor */
Config::~Config()
{
   if (src_ip)
   {
      free(src_ip);
   }
   if (dst_ip)
   {
      free(dst_ip);
   }
   if (dev)
   {
      free(dev);
   }
   if (output_file)
   {
      free(output_file);
   }
}


/* automatically set dev */
int Config::set_source_iface() 
{
   struct ifaddrs* ifAddrStruct = NULL;
   struct ifaddrs* ifa = NULL;
   
   getifaddrs(&ifAddrStruct);
   for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) 
   {
      if (ifa ->ifa_addr->sa_family == AF_INET) 
      { 
	 //we do not need lo iface
	 if (!strncasecmp(ifa->ifa_name, "lo", 2)) continue;
	 dev = strdup(ifa->ifa_name);
	 set_source_IP(dev);

	 freeifaddrs(ifAddrStruct);
	 return 1;
      }
      else
      {
	 continue;
      }
   }
   freeifaddrs(ifAddrStruct);
   return 0;
}

/* automatically set src_ip and sip */
int Config::set_source_IP(char* ifname)
{
   struct ifaddrs* ifAddrStruct = NULL;
   struct ifaddrs* ifa = NULL;
   char addrBuf[INET_ADDRSTRLEN];
   
   if (ifname == NULL)
   {
      return 0;
   }

   getifaddrs(&ifAddrStruct);
   for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) 
   {
      if (ifa->ifa_addr->sa_family == AF_INET) 
      { 
	 // find the IP address of the ifname
	 if (!strcmp(ifa->ifa_name, ifname)) 
	 {
	    logger->PrintDebug("[%s:%d] ifname is %s\n", __FILE__, __LINE__, ifname);
	    inet_ntop(ifa->ifa_addr->sa_family, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, addrBuf, INET_ADDRSTRLEN);
	    src_ip = strdup(addrBuf);
	    sip = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
	    freeifaddrs(ifAddrStruct);
	    return 1;
	 }
	 continue;
      }
      else
      {
	 continue;
      }
   }
   freeifaddrs(ifAddrStruct);
   return 0;
}

/* automatically set dst_ip, dip and dst_port (recognize domain name) */
int Config::set_dest_IP(char* address)
{
   char* addr;
   char port[10];
   struct addrinfo hints;
   struct addrinfo *result;
   int s;
   char addrBuf[INET_ADDRSTRLEN];

   // seperating port number from address, default port number is HTTP_PORT
   if (strstr(address, ":"))
   {
      addr = strtok(address, ":");
      dst_port = atoi(strtok(NULL, ":"));
   }
   else
   {
      addr = address;
      dst_port = HTTP_PORT;
   }
   sprintf(port, "%d", dst_port);

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
   hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
   hints.ai_protocol = 0;          /* Any protocol */
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;
   s = getaddrinfo(addr, port, &hints, &result);
   if (s != 0 )
   {
      logger->PrintErr("[%s:%d] getaddrinfo: %s\n", __FILE__, __LINE__, gai_strerror(s));
      exit(EXIT_FAILURE);
      return -1;
   }
   inet_ntop(result->ai_addr->sa_family, &((struct sockaddr_in*)result->ai_addr)->sin_addr, addrBuf, INET_ADDRSTRLEN);
   dst_ip = strdup(addrBuf);
   dip = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;

   logger->PrintDebug("[%s:%d] addr is %s and port number is %d\n", __FILE__, __LINE__, dst_ip, dst_port);
   
   return 0;
}


/* set a default output file to store pcap file */
void Config::set_default_output_file()
{
   struct timeval t;
   char str[1024];
   gettimeofday(&t, NULL);  
   snprintf(str, 1024, "%s.%d_%lu.%06lu.pcap", dst_ip, dst_port, t.tv_sec, t.tv_usec);
   output_file = strdup(str);
}



