#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <linux/if_arcnet.h> 
#include <linux/version.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>

char *interface = NULL;
int pd = -1;

void sigint(int signum) {
	struct ifreq ifr;
	if (pd == -1) {
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ioctl(pd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags &= -IFF_PROMISC;
	ioctl(pd, SIOCSIFFLAGS, &ifr);

	close(pd);
	exit(0);
}

void print_ethaddr(const u_char *p) {
	int i;
	struct ethhdr *eh;

	eh = (struct ethhdr *)p;

	// h_proto is a __be16, means big-endian
	// 0x0800 is ETH_P_IP
	printf("0x%04x ", ntohs(eh->h_proto));

	// mac address is 6 bytes
	printf("MAC: ");
	for (i=0; i < 5; i++) {
		printf("%02x:", (int)eh->h_source[i]);
	}
	printf("%02x -> ", (int)eh->h_source[i]);

	for (i=0 ; i < 5; ++i) {
		printf("%02x:", (int)eh->h_dest[i]);
	}
	printf("%02x", (int)eh->h_dest[i]);
	printf("\n");

	if (ntohs(eh->h_proto) == ETH_P_IP) {
		struct iphdr *iph = (struct iphdr *)(p + sizeof(struct ethhdr));
		printf("protocol:0x%02x ", iph->protocol);
		printf("header_length:%d ", iph->ihl * 4);
		printf("total_length: %d\n", ntohs(iph->tot_len));

		printf("IP: ");
		unsigned int source = ntohl(iph->saddr);
		for (i=0; i < 3; i++) {
			printf("%d.", source << (8 * i) >> 24);
		}
		printf("%d -> ", source << ( 8 * i) >> 24);

		unsigned int destination = ntohl(iph->daddr);
		for (i=0; i < 3; i++) {
			printf("%d.", destination << (8 * i) >> 24);
		}
		printf("%d\n", destination << ( 8 * i) >> 24);

		// tcp: 0x06, udp: 0x11
		if (iph->protocol == 0x06) {
			struct tcphdr *tcph = (struct tcphdr *)(p + sizeof(struct ethhdr) + iph->ihl * 4);
			printf("seq: %u\n", ntohl(tcph->seq));
			printf("port: %u -> %u\n", ntohs(tcph->source), ntohs(tcph->dest));

			const unsigned char *payload = p + sizeof(struct ethhdr) + iph->ihl * 4 + tcph->th_off * 4;
			int payload_size = ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct tcphdr);
			printf("(%d) ", payload_size);
			for (int i=0; i < payload_size; i++) {
				printf("%c", payload[i]);
			}
			printf("\n");
		}
	}
}

void print_arcaddr(const u_char *p) {
}


void hexdump(unsigned char *buf, int len) {
	for (int j=0; j < len; j++) {
		printf("%02x", buf[j]);
	}
	printf("\n");
}

int main(int argc, char** argv) {
	int c;
	unsigned char buf[2048];
	unsigned char* p;
	struct sockaddr_ll sll;
	int i;
	struct ifreq ifr;
	int ifindex;
	struct sockaddr myaddr;
	int addrlen;

	for (;;) {
		c = getopt(argc, argv, "i:");
		switch(c) {
			case 'i':
				interface = strdup(optarg);
				break;
			case -1:
				break;
			default:
				fprintf(stderr, "usage: %s -i interface\n", argv[0]);
				exit(1);
		}
		if (c == -1) {
			break;
		}
	}

	if (interface == NULL) {
		fprintf(stderr, "usage: %s -i interface\n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sigint);

	// ETH_P_ALL: handle all packet from data-link layer
	pd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (pd == -1) {
		perror("socket():");
		exit(1);
	}

	// get interface index number
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(pd, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("get interface index: %d\n", ifindex);

	// get hardware address
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(pd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}
	myaddr = ifr.ifr_hwaddr;


	switch (myaddr.sa_family) {
	case ARPHRD_ARCNET:
		// address length for arcnet
		addrlen = 1;
		break;
	case ARPHRD_ETHER:
		// address length for ethernet(MAC address)
		addrlen = 6;
		break;
	default:
		addrlen = sizeof(myaddr.sa_data);
	}

	printf("get hardware address: ");
	printf("family = %d, address = ", myaddr.sa_family);
	p = myaddr.sa_data;
	for (i = 0; i < addrlen - 1; i++) {
		printf("%02x:", *p++);
	}
	printf("%02x\n", *p);

	// promiscous mode
	printf("set promiscous mode\n");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	// get flag
	ioctl(pd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	// enable promiscous mode and set flag
	ioctl(pd, SIOCSIFFLAGS, &ifr);

	printf("bind to %s\n", interface);


	// bind socket
	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;
	if (bind(pd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		perror("bind():");
		exit(1);
	}

	// flush all received packets
	printf("flush receive buffer\n");
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);
		FD_SET(pd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0) {
			int len = recv(pd, buf, sizeof(buf), 0);
			for (int j=0; j < len; j++) {
				printf("%02x", buf[j]);
			}
			printf("\n");
		}
	} while (i);

	printf("start receiving\n");

	for (;;) {
		i = recv(pd, buf, sizeof(buf), 0);
		if (i < 0) {
			perror("recv():");
			exit(1);
		}
		if (i == 0) {
			continue;
		}

		switch (myaddr.sa_family) {
		case ARPHRD_ETHER:
			print_ethaddr(buf);
			break;
		case ARPHRD_ARCNET:
			print_arcaddr(buf);
			break;
		default:
			printf("sa_family: %x\n", myaddr.sa_family);
		}
		// hexdump(buf, i);
	}

	return 0;
}
