all:
	gcc ws-client.c -o ws-client -lssl -lcrypto

clean:
	rm -f ws-client ws-client.o
