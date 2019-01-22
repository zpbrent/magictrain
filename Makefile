MAIN = mtrain 
CXX = g++
DEBUG = -g #-O0 -v -da -Q
LIBS = -lm -lrt -lpthread -lpcap #-lssl -lcrypto #-L../libpcap-1.0.0 
INCLUDES = -I. #-I../libpcap-1.0.0 


CFLAGS = -O2 -Wall  
OBJS = common.o log.o config.o asyncBuffer.o packet.o pcapCore.o rawSocketCore.o tranHandler.o th_rawpcap.o trainEngine.o 

all: $(MAIN)

%.o: %.cpp %.h
	$(CXX) $(CFLAGS) $(DEBUG) $(INCLUDES) -c $< -o $@

$(MAIN): main.cpp $(OBJS)
	$(CXX) $(CFLAGS) $(DEBUG) $(INCLUDES) -o $@ main.cpp $(OBJS) $(LIBS) 

backup:
	tar --directory ../ -zcvf ../mtrain_`date +%y%m%d`.tar.gz mtrain

clean:
	@rm -f *.o
	@rm -f $(MAIN)
