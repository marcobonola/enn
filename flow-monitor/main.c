#include "enn-flow-monitor.h"


pcap_t *handle;				/* packet capture handle */
struct bpf_program fp;			/* compiled filter program (expression) */

/*
 * print help text
 */
void
print_app_usage(void) {
	printf("Usage: %s <capture_mode> <source>\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("<capture_mode> 0 live mode, 1 offline\n");
	printf("<source> interface name (live mode) or pcap file name (offline)\n");
	printf("<num> number of packets to capture. 0 == infinite (ctrl-c to exit)\n");
	printf("<debug> 0 silent mode, 1 verbose mode, 2 super verbose mode\n");
	printf("\n");
}

/*
 * ctrl-c handler. just return
 * */
void INThandler(int sig) {
	/* returned from the pcap loop */
	flow_db_dump();

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");


	exit(0);
}


int main(int argc, char **argv) {
	char *source = NULL;			/* capture device name */
	int type = 0;				/* 0 live, 1 offline */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	char filter_exp[] = "ip";		/* filter expression [3] */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets;			/* number of packets to capture */
	
	/* check for capture device name on command-line */
	if (argc == 5) {
		type = atoi(argv[1]);
		source = argv[2];
		num_packets = atoi(argv[3]);
		debug = atoi(argv[4]);
	}
	else if (argc > 5) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	

	if (type == CAPTURE_TYPE_LIVE) {
		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(source, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", source, errbuf);
			net = 0;
			mask = 0;
		}

		/* print capture info */
		printf("Device: %s\n", source);
		printf("Number of packets: %d\n", num_packets);
		printf("Filter expression: %s\n", filter_exp);

		/* open capture device */
		handle = pcap_open_live(source, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", source, errbuf);
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", source);
			exit(EXIT_FAILURE);
		}
	}

	if (type == CAPTURE_TYPE_OFFLINE) {
		handle = pcap_open_offline(source,  errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", source, errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* signal handler */
	signal(SIGINT, INThandler);

	/* flow DB init() */
	flow_db_init();

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	return 0;
}

