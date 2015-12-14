magictrain
==========

A bandwidth measurement tool against bandwidth inflation attacks

==========
apt-get install libpcap-dev
make

==========
Usage: ./mtrain [options] [IP or DNS of target prover]
Options:
  -i iface name. Without -i, mtrain will find iface automatically
  -e Train type. 0 is TIME_TRAIN, 1 is OF_TRAIN and 2 is SYN_TRAIN
  -n How many trains used. Default is 3.
  -s Train length. Default is 100.
  -m 0=libpcap+rawSocket, 1=kernel+libnetfilter_queue.
     Packet transmission method selection. Default is 0.
  -d DEBUG info. enabled.
  -o Enable output pcap.
  -t For test supporting rate purpose only.
  -r For RTT estimation only.
  -p For packet pair measurement only.
  -? Print HELP info..
