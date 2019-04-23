all: client.out server.out

server.out:
	gcc -Wall -g -o server.out server.c -lcrypto -lssl

client.out:
	gcc -Wall -g -o client.out client.c -lcrypto -lssl