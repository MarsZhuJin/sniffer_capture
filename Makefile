CC=gcc
CFLAGS=-g -O0

SOURCE_FILE=sniffer_capture.c
OBJ_FILE=sniffer_capture

Packet_Capture: $(SOURCE_FILE)
	$(CC) $(CFLAGS) $(SOURCE_FILE) -o $(OBJ_FILE) -lpcap -lhiredis -lpthread

clean:
	-rm -f $(OBJ_FILE)
