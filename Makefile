OBJECTS = main.o keyblock.o crc32.o newcamd.o cs378x.o vm_api.o ssl-client.o tcp-client.o md5crypt.c

default: vmcam

%.o: %.c
	gcc -c $< -o $@

vmcam: $(OBJECTS)
	gcc $(OBJECTS) -lssl -lcrypto -lpthread -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f program