#Makefile
.PHONY:all
all:test_net_device

test_net_device:net_device.o util.o sk_buff.o arp.o eth.o ip.o icmp.o udp.o
	gcc -o $@ $^

%.o:%.c
	gcc -c $<

.PHONY:clean
clean:
	rm *.o test_net_device
