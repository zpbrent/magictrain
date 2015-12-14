/*
 * rawpcap class for handling packet sending and receiving using raw socket + pcap
 * raw packet is used to send packet while pcap is for packet receiving
*/

#include <unistd.h>
#include <sys/wait.h>
#include "th_rawpcap.h"
#include "log.h"

extern Log* logger;

/* Constructor */
TH_RawPcap::TH_RawPcap(Config* conf)
{
   conf_ = conf;
   sock_ = new RawSocket(conf->get_dip(), conf->get_dst_port(), conf->get_src_port());
   pcap_ = new Pcap(conf->get_dev(), conf->get_snaplen(), conf->get_src_ip(), conf->get_dst_ip(), conf->get_src_port(), conf->get_dst_port(), conf->get_output_file(), &th_process_packet);
   launch_iptable_rule();
}

/* Destructor */
TH_RawPcap::~TH_RawPcap()
{
   th_cleanup();
}

/* send a packet */
int TH_RawPcap::th_send_packet(Packet* pkt)
{
   return sock_->send(pkt);
}

/* start a pcap thread to capture packets */
int TH_RawPcap::th_start_capture()
{
   return pcap_->start_thread();
}

/* cleanup */
int TH_RawPcap::th_cleanup()
{
   delete_iptable_rule();
   if (pcap_)
   {
      delete pcap_;
   }
   if (sock_)
   {
      delete sock_;
   }
   return 0;
}

/* launch a firewall to filter out possible RST packets trigerred by SYN+ACK */
/* /sbin/iptables -I OUTPUT --protocol tcp --tcp-flags RST RST -d [dst_ip] --dport [dst_port] -j DROP */
int TH_RawPcap::launch_iptable_rule()
{
   char cmd[512];
   int status;

   sprintf(cmd, "/sbin/iptables -I OUTPUT --protocol tcp --tcp-flags RST RST -d %s --dport %d --match ttl --ttl-lt %u -j DROP", conf_->get_dst_ip(), conf_->get_dst_port(), TTL);
   switch (fork()) 
   {
      case -1:
	 logger->PrintErr("[%s:%d] Err: launch\n", __FILE__, __LINE__);
	 return -1;
	 break;
      case 0:
	 // child process
	 if (setsid() < 0) 
	 {
	    //Log any failure
	    _exit(-1);
	 }
	 execl("/bin/sh","/bin/sh", "-c", cmd,  (char *)0);
	 logger->PrintErr("[%s:%d] Err: execl\n", __FILE__, __LINE__);
	 _exit(-1);
	 break;
      default:
	 //parent process
	 wait(&status);
	 break;
   }
   logger->PrintDebug("[%s:%d] iptable insert: %s\n", __FILE__, __LINE__, cmd);
   return 0; 
}


/* delete a firewall to filter out possible RST packets trigerred by SYN+ACK */
/* /sbin/iptables -D OUTPUT --protocol tcp --tcp-flags RST RST -d [dst_ip] --dport [dst_port] -j DROP */
int TH_RawPcap::delete_iptable_rule()
{
   char cmd[512];
   int status;

   sprintf(cmd, "/sbin/iptables -D OUTPUT --protocol tcp --tcp-flags RST RST -d %s --dport %d --match ttl --ttl-lt %u -j DROP", conf_->get_dst_ip(), conf_->get_dst_port(), TTL);
   switch (fork()) 
   {
      case -1:
	 logger->PrintErr("[%s:%d] Err: launch\n", __FILE__, __LINE__);
	 return -1;
	 break;
      case 0:
	 // child process
	 if (setsid() < 0) 
	 {
	    //Log any failure
	    _exit(-1);
	 }
	 execl("/bin/sh","/bin/sh", "-c", cmd,  (char *)0);
	 logger->PrintErr("[%s:%d] Err: execl\n", __FILE__, __LINE__);
	 _exit(-1);
	 break;
      default:
	 //parent process
	 wait(&status);
	 break;
   }
   logger->PrintDebug("[%s:%d] iptable delete: %s\n", __FILE__, __LINE__, cmd);
   return 0; 
}



