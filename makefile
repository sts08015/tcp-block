CC = g++
CXXFLAGS = -std=c++17
LDLIBS = -lpcap

all: tcp-block

tcp-block: tcp-block.o ethhdr.o ip.o mac.o
	$(CC) $^ $(CXXFLAGS) $(LDLIBS) -o $@

clean:
	@rm -f *.o tcp-block

remake: clean all
