CC = g++
CXXFLAGS = -std=c++17
LDLIBS = -lpcap

all: tcp-block

tcp-block: ethhdr.o ip.o mac.o tcp-block.o
	$(CC) $^ $(CXXFLAGS) $(LDLIBS) -o $@

clean:
	@rm -f *.o tcp-block

remake: clean all
