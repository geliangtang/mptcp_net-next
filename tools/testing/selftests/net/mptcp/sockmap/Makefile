CC = gcc
CFLAGS = -I/usr/include/bpf
LDFLAGS = -lbpf

TARGET = sockhash_example
SRCS = sockhash_example.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
