CC=gcc
CFLAGS=-g -O0

SOURCE_FILE=Packet_Capture.c
OBJ_FILE=Packet_Capture

Packet_Capture: $(SOURCE_FILE)
	$(CC) $(CFLAGS) $(SOURCE_FILE) -o $(OBJ_FILE) -lpcap -lhiredis -lpthread

clean:
	-rm -f $(OBJ_FILE)
