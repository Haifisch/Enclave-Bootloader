TARGET=imagemaker
CFLAGS=-O2 -pipe
CC=gcc
OBJECTS=image3maker.o c25519.o ed25519.o edsign.o f25519.o fprime.o morph25519.o sha256.o sha512.o cdecode.o cencode.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS)
