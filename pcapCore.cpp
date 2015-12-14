/*
 * pcapcore.cpp
 * - Pragram for handling pcapcore functions 
 */
#include <netdb.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <string.h>
#include "pcapCore.h"
#include "common.h"
#include "log.h"

extern Log* logger;

void* pcap_obj; // used for store one Pcap object 

/* Constructor */
Pcap::Pcap(char *dev, int snaplen, char *src_ip, char *dst_ip, int src_port, int dst_port, char *output_file, void (*p)(Packet* pkt))
{
   char errbuf[100];
   char d[] = "any";
   int datalinktype;

   //init variables
   hd = NULL;
   pd = NULL;
   dataLinkOffset = 0;
   isOpen = false;
   process_thread = 0;
   last_pcap_time = 0;
   process_packet = NULL;

   if (dev == NULL) 
   {
      dev = d;	//assume using "any" iface if dev = NULL
   }
   
   hd = pcap_open_live(dev, snaplen, 1, 10, errbuf);
   
   if (hd == NULL) 
   {
      logger->PrintErr("[%s:%d] Pcap cannot listen on device\n", __FILE__, __LINE__);
   } 
   else 
   {
      isOpen = true;
   }

   if ((datalinktype = pcap_datalink(hd)) < 0) 
   {
      destroy();
      logger->PrintErr("[%s:%d] Pcap unable to determine datalink type\n", __FILE__, __LINE__);
   }

   switch(datalinktype) 
   {
      case DLT_EN10MB: 
	 dataLinkOffset = DLT_EN10MB_LEN; 
	 break;
      case DLT_IEEE802: 
	 dataLinkOffset = DLT_IEEE802_LEN; 
	 break;
      case DLT_NULL: 
	 dataLinkOffset = DLT_NULL_LEN; 
	 break;
      case DLT_SLIP: 
	 dataLinkOffset = DLT_SLIP_LEN; 
	 break;
      case DLT_PPP: 
	 dataLinkOffset = DLT_PPP_LEN; 
	 break;
      case DLT_RAW: 
	 dataLinkOffset = DLT_RAW_LEN; 
	 break;
      case DLT_LINUX_SLL: 
	 dataLinkOffset = DLT_LINUX_SLL_LEN; 
	 break;	//this is used to support "any" device type in linux
      default:
	 destroy();
	 logger->PrintErr("[%s:%d] Pcap unknown datalink type\n", __FILE__, __LINE__);
   }

   if (pcap_setnonblock(hd, 0, errbuf) < 0) 
   {	//set the pcap to non-blocking mode
      destroy();
      logger->PrintErr("[%s:%d] Pcap unable to set pcap_setnonblock\n", __FILE__, __LINE__);
   }

   add_filter(src_ip, src_port, dst_ip, dst_port);
   if(output_file)
   {
      add_dump(output_file);
   }
   if(p != NULL) 
   {
      process_packet = p;
   }
}

Pcap::~Pcap() 
{
   destroy();
}

/* Pcap capture loop */
void* Pcap::process_thread_func_(void* p_arg)
{
   Pcap *p = (Pcap *)p_arg;
   pcap_loop(p->hd, -1, &pcap_next_wrapper_, (u_char *)p->pd);
   return NULL;
}

/* resolve the static and object's element conflict */
void Pcap::pcap_next_wrapper_(u_char *pd, const struct pcap_pkthdr* pkthdr, const u_char* packetBuf)
{
   if (pcap_obj == NULL)
   { 
      return;
   }
   Pcap* pcap = (Pcap*)pcap_obj;
   pcap->pcap_next_(pd, pkthdr, packetBuf);
}

/* capture the next packet */
void Pcap::pcap_next_(u_char *pd, const struct pcap_pkthdr* pkthdr, const u_char* packetBuf) 
{
   if(process_packet != NULL) 
   {
      Packet* pkt = (Packet *)new Packet(packetBuf + dataLinkOffset, pkthdr->len - dataLinkOffset, tv2ts(pkthdr->ts));
      (*process_packet)(pkt);
      // save the packets into the dump file.
      if(pd) 
      {
	 pcap_dump(pd, pkthdr, packetBuf);
      }
   }
}


int Pcap::start_thread() 
{
   int ret;
   if(!isOpen)
   {
      return -1;
   }
   
   // this is a must, due to stupid C++ and the pcap_handler!
   pcap_obj = (void*) this;		
   
   // the function pointer process_thread_func_ should be a static function
   ret = pthread_create(&process_thread, NULL, process_thread_func_, this);		
   return ret;
}

void Pcap::destroy() 
{
   // if the pcap is not open, do not need to destroy;
   if(!isOpen) 
   {
      return;
   }

   pcap_breakloop(hd);
   pthread_join(process_thread, NULL);
   
   // kill the capturing thread!
   //pthread_cancel(pcap_.process_thread);
   
   if(pd != NULL) 
   {
      pcap_dump_flush(pd);
      pcap_dump_close(pd);
      pd = NULL;
   }
   
   pcap_close(hd);
   hd = NULL;
   isOpen = false;
   logger->PrintDebug("[%s:%d] Pcap deleted\n", __FILE__, __LINE__);
}

void Pcap::add_dump(char *file) 
{
   if(!isOpen || file==NULL) 
   {
      return;
   }
   
   if ((pd = pcap_dump_open(hd,file)) == NULL) 
   {
      logger->PrintErr("[%s:%d] Pcap cannot open the dump file. Pcap output disabled.\n", __FILE__, __LINE__);
      pd = NULL;
      //destroy();
      return;
   }
}

/* add a filter to capture the traffic that we want */
int Pcap::add_filter(char *src_ip, int src_port, char *dst_ip, int dst_port) 
{
   char filter_exp[256];
   struct bpf_program fp;		/* The compiled filter expression */

   if(!isOpen || src_ip == NULL || dst_ip == NULL) 
   {
      return -1;
   }

   sprintf(filter_exp, "( tcp and host %s and host %s and port %d )", src_ip, dst_ip, dst_port);
   logger->PrintDebug("[%s:%d] %s\n", __FILE__, __LINE__, filter_exp);
   if (pcap_compile(hd, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
   {
      logger->PrintErr("[%s:%d] Pcap filter compilation error.\n", __FILE__, __LINE__);
      destroy();
      return -1;
   }
	
   if (pcap_setfilter(hd, &fp) == -1) 
   {
      logger->PrintErr("[%s:%d] Pcap filter won't install.\n", __FILE__, __LINE__);
      destroy();
      return -1;
   }
   return 0;
}

