all: tcp-block

tcp-block:
	g++ -o tcp-block tcp-block.cpp -lpcap

clean:
	rm -f tcp-block

remake: clean all
