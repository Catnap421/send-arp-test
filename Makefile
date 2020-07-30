all: send-arp-test

send-arp-test: main.cpp
	g++ -o send-arp-test main.cpp -lpcap
	
clean:
	rm send-arp-test
