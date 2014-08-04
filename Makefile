OBJECTS = main.o keyblock.o crc32.o newcamd.o cs378x.o vm_api.o ssl-client.o tcp-client.o md5crypt.o

default: vmcam

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

vmcam: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -lssl -lcrypto -lpthread -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f vmcam
