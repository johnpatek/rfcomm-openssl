all: client server

client.o:
	gcc -c client.c

server.o:
	gcc -c server.c

client: client.o
	gcc -o client client.o -lbluetooth -lssl -lcrypto

server: server.o
	gcc -o server server.o -lbluetooth -lssl -lcrypto

clean:
	rm *.o client server