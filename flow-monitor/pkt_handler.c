#include "enn-flow-monitor.h"

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	//const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const unsigned char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	if (debug) printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	//ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		if (debug) printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	if (debug) {
		printf("  From: %s\n", inet_ntoa(ip->ip_src));
		printf("  To: %s\n", inet_ntoa(ip->ip_dst));

	
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				printf("  Protocol: TCP\n");
				break;
			case IPPROTO_UDP:
				printf("  Protocol: UDP\n");
				break;
			case IPPROTO_ICMP:
				printf("  Protocol: ICMP\n");
				break;
			case IPPROTO_IP:
				printf("  Protocol: IP\n");
				break;
			default:
				printf("  Protocol: unknown\n");
				break;
		}
	}
	
	/*
	 *  If packet != TCP return
	 */
	if (ip->ip_p != IPPROTO_TCP) return;

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		if (debug) printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	if (debug) {
		printf("  Src port: %d\n", ntohs(tcp->th_sport));
		printf("  Dst port: %d\n", ntohs(tcp->th_dport));
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0 && debug > 1) {
		printf("  Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	/*
	 * build the flow key 
	 * */
	struct flow_key *fk;
	fk = malloc(sizeof (struct flow_key));
	memset(fk, 0, sizeof(struct flow_key));

	memcpy(&fk->ipsrc, &ip->ip_src, 4);
	memcpy(&fk->ipdst, &ip->ip_dst, 4);
	fk->ipproto = (uint8_t) ip->ip_p;
       	fk->srcport = (uint16_t) tcp->th_sport;
	fk->dstport = (uint16_t) tcp->th_dport;
	
	if (debug) {
		int i;
		uint8_t * x = (uint8_t *)fk;
		printf("  Flow key: ");
		for (i=0; i<sizeof(struct flow_key); i++) 
			printf("%02x", x[i]);
		printf("\n");
	}

	if (flow_measure_and_update_db(fk, (int) (ip->ip_len + SIZE_ETHERNET), header->ts) < 0) {
		if (debug) printf("There was an error updating flow DB\n");
	}
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

