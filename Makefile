
all: sniffer spoffer snoffer gateway

sniffer: Sniffer.c
	gcc Sniffer.c -o sniff -lpcap
	
spoffer: Spoffer.c
	gcc Spoffer.c -o spoff

snoffer: Snoffer.c
	gcc Snoffer.c -o snoff -lpcap

gateway: Gateway.c
	gcc Gateway.c -o gate

.PHONY: clean all

clean:
	rm -f spoff sniff snoff gate
	
