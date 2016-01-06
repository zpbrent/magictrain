magictrain
==========

A bandwidth measurement tool against bandwidth inflation attacks

==========
apt-get install libpcap-dev<br>
make

==========
Usage: <br>
./mtrain [options] [IP or DNS of target prover]<br>
Options:<br>
  -i iface name. Without -i, mtrain will find iface automatically<br>
  -e Train type. 0 is TIME_TRAIN, 1 is OF_TRAIN and 2 is SYN_TRAIN<br>
  -n How many trains used. Default is 3.<br>
  -s Train length. Default is 100.<br>
  -m 0=libpcap+rawSocket, 1=kernel+libnetfilter_queue. Packet transmission method selection. Default is 0.<br>
  -d DEBUG info. enabled.<br>
  -o Enable output pcap.<br>
  -t For test supporting rate purpose only.<br>
  -r For RTT estimation only.<br>
  -p For packet pair measurement only.<br>
  -? Print HELP info..

==========
If you use our tool, please cite the paper at:<br>

@article{zhou2015magic,<br>
  title={Magic Train: Design of Measurement Methods Against Bandwidth Inflation Attacks},<br>
  author={Zhou, Peng and Chang, Rocky KC and Gu, Xiaojing and Fei, Minrui and Zhou, Jianying},<br>
  journal={IEEE Transactions on Dependable and Secure Computing},<br>
  year={2015},<br>
  publisher={IEEE}<br>
}<br>
