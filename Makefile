GSOAP_ROOT = ./
CC = gcc -g  -DWITH_OPENSSL -DWITH_DOM -DSOAP_DEBUG -DDEBUG
INCLUDE = -I$(GSOAP_ROOT)
SERVER_OBJS = dom.o soapC.o stdsoap2.o  wsaapi.o wsseapi.o smdevp.o mecevp.o threads.o onvif_server_interface.o soapClient.o soapServer.o onvif_server.o

all: server 
server: $(SERVER_OBJS)
	$(CC) $(INCLUDE) -g -o deviceserver $(SERVER_OBJS) -lpthread -lssl -lcrypto

clean: 
	rm -f *.o deviceprobe  deviceserver onvif
