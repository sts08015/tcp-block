all: tcp-block

tcp-block:
	g++ -std=c++17 -o tcp-block tcp-block.cpp -lpcap

clean:
	rm -f tcp-block

remake: clean all
