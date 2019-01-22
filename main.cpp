/*
 * Magic train implementation
 *  
 * Author: Zhou Peng
 * E-mail: zpbrent@gmail.com
 *  
 * All copy rights reserved. 
 *
 * Last modified for release!
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>    /* for getopt */
#include <signal.h>
#include "log.h"
#include "config.h"
#include "common.h"
#include "tranHandler.h"
#include "th_rawpcap.h"
#include "trainEngine.h"
#include "asyncBuffer.h"

#define TEST_PORT 25500
#define MEASUREMENT_PORT 26000

Log* logger = NULL;
Config* conf = NULL;
TranHandler* thandler = NULL;
TrainEngine* mtrain = NULL;
AsyncBuffer* globalBuf = NULL;

void usage()
{
   fprintf(stderr, "Usage: ./mtrain [options] [IP or DNS of target prover]\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "  -i iface name. Without -i, mtrain will find iface automatically\n");
   fprintf(stderr, "  -e Train type. 0 is TIME_TRAIN, 1 is OF_TRAIN and 2 is SYN_TRAIN\n");
   fprintf(stderr, "  -n How many trains used. Default is 3.\n");
   fprintf(stderr, "  -s Train length. Default is 100.\n");
   fprintf(stderr, "  -m 0=libpcap+rawSocket, 1=kernel+libnetfilter_queue.\n");
   fprintf(stderr, "     Packet transmission method selection. Default is 0.\n");
   fprintf(stderr, "  -d DEBUG info. enabled.\n");
   fprintf(stderr, "  -o Enable output pcap.\n");
   fprintf(stderr, "  -t For test supporting rate purpose only.\n");
   fprintf(stderr, "  -r For RTT estimation only.\n");
   fprintf(stderr, "  -p For packet pair measurement only.\n");
   fprintf(stderr, "  -? Print HELP info..\n");
}

void cleanup()
{
   if (thandler)
   {
      thandler->th_cleanup();
      delete thandler;
   }
   if (conf)
   {
      delete conf;
   }
   if (logger)
   {
      delete logger;
   }
   if (globalBuf)
   {
      delete globalBuf;
   }
}

static void SignalHandler (int sig, siginfo_t *siginfo, void *context)
{
   switch(sig) 
   {
      case SIGINT:
      case SIGTERM:
      case SIGKILL:
	 logger->PrintLog("[%s:%d] Signal catched! Terminating...\n", __FILE__, __LINE__);
	 cleanup();
	 exit(0);
	 break;
   }
}


int main(int argc, char ** argv)
{
   int opt;
   bool isOutput = false;
   double* bw;
   double* t1;
   double* dropNum;
   double* capacity;


   signal(SIGINT, SIG_IGN);
   signal(SIGTERM, SIG_IGN);
   signal(SIGKILL, SIG_IGN);

   //catch SIGINT, SIGTERM and SIGKILL
   struct sigaction act;
   memset (&act, '\0', sizeof(act));
   act.sa_sigaction = &SignalHandler;
   act.sa_flags = SA_SIGINFO;
   sigaction(SIGINT, &act, NULL);
   sigaction(SIGTERM, &act, NULL);
   sigaction(SIGKILL, &act, NULL);

   logger = new Log();
   conf = new Config();

   
   while ((opt = getopt(argc, argv, "n:e:tproi:s:m:d?")) != -1) 
   {
      switch(opt) 
      {
	 case 'n':
	    conf->set_round_num(atoi(optarg));
	    break;
	 case 'e':
	    conf->set_train_type(atoi(optarg));
	    break;
	 case 't':
	    conf->set_test(true);
	    break;
	 case 'r':
	    conf->set_RTT_est(true);
	    break;
	 case 'p':
	    conf->set_pp_measure(true);
	    break;
	 case 'i':
	    conf->set_dev(strdup(optarg));
	    conf->set_source_IP(conf->get_dev());
	    break;
	 case 's':
	    break;
	 case 'o':
	    isOutput = true;
	    break;
	 case 'd':
	    // enable debug
	    logger->set_debug();
	    conf->set_debug(true);
	    break;
	 case 'm':
	    break;
	 case '?':
	 default:
	    usage();
	    exit(1);
	    break;
      }
   }

   
   logger->PrintDebug("[%s:%d] Target Prover is %s\n", __FILE__, __LINE__, argv[optind]);

   if (conf->set_dest_IP(argv[optind]) < 0)
   {
      return -1;
   }
   if (isOutput)
   {
      conf->set_default_output_file();
   }

   logger->PrintDebug("[%s:%d] DEV is %s\n", __FILE__, __LINE__, conf->get_dev());

   logger->PrintDebug("[%s:%d] Source IP is %s\n", __FILE__, __LINE__, conf->get_src_ip());

   // create a global buffer to store captured packet
   globalBuf = new AsyncBuffer();

   // transmission handler init
   thandler = new TH_RawPcap(conf);
   thandler->th_start_capture();

   // magic train init
   mtrain = new TrainEngine(conf, thandler);

   //mtrain->gen_tcp_syn();
   //mtrain->send_train();
   
   // for supporting rate test purpose
   if (conf->is_test())
   {
      mtrain->test(MEASUREMENT_PORT, 1000, 300);
   }
   // for RTT estimation
   else if (conf->is_RTT_est())
   {
      mtrain->RTT_est(MEASUREMENT_PORT, 1000, 300);
   }
   // for measurement
   else
   {
      srand (time(NULL));
      bw = new double[conf->get_round_num()];
      t1 = new double[conf->get_round_num()];
      dropNum = new double[conf->get_round_num()];
      capacity = new double[CAPNUM-1];
      for (int i=0; i < conf->get_round_num(); i++)
      {
	 if (conf->get_train_type() == OF_DATA)
	 {
	    if (conf->is_pp_measure())
	    {
	       mtrain->measure(conf->get_train_type(), 2, MEASUREMENT_PORT, 1000, 300);
	    }
	    else
	    {
	       mtrain->measure(conf->get_train_type(), rand()%41+10, MEASUREMENT_PORT, 1000, 300);
	    }
	 }
	 else
	 {
	    if (conf->is_pp_measure())
	    {
	       mtrain->measure(conf->get_train_type(), 2, MEASUREMENT_PORT + i, 1000, 300);
	    }
	    else
	    {
	       mtrain->measure(conf->get_train_type(), rand()%41+10, MEASUREMENT_PORT + i, 1000, 300);
	    }
	 }
	 bw[i] = mtrain->get_bw();
	 t1[i] = mtrain->get_t1();
	 dropNum[i] = mtrain->get_dropNum();
      }
      // we only care the capacity reported by the first 10 measurement packets
      for (int i=0; i < CAPNUM-1; i++)
      {
	 capacity[i] = mtrain->get_capacity(i+1);
      }
      //mtrain->measure_time_data(50, MEASUREMENT_PORT, 1000, 300);
      //mtrain->measure_of_data(100, MEASUREMENT_PORT, 1000);
      //mtrain->measure_syn_data(50, MEASUREMENT_PORT, 1000);
      logger->PrintLog("t1: mean is %f, standard deviation is %f\n", cal_mean(t1, conf->get_round_num()), cal_sd(t1, conf->get_round_num()));
      logger->PrintLog("bw: mean is %f, standard deviation is %f\n", cal_mean(bw, conf->get_round_num()), cal_sd(bw, conf->get_round_num()));
      logger->PrintLog("dropNum: mean is %f, standard deviation is %f\n", cal_mean(dropNum, conf->get_round_num()), cal_sd(dropNum, conf->get_round_num()));
      logger->PrintLog("capacity: mean is %f, standard deviation is %f\n", cal_mean(capacity, CAPNUM-1), cal_sd(capacity, CAPNUM-1));
      delete[] bw;
      delete[] t1;
      delete[] dropNum;
      delete[] capacity;
   }

   cleanup();

   return 0;
}

