#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include "../src/sharecap.h"


extern char *optarg;    /* Variables used for getopt(3) */
extern int optind;
extern int opterr;
extern int optopt;

ShareCapProcess *scp=NULL;
pcap_t *p=NULL;

void terminate(int signal) {
	if (!scp) exit(EXIT_SUCCESS);

	/* remove this part in different case */
	sleep(1);
	ShareCapMasterRemovePackets(scp);

	printf("waiting %d clients to exit:\n",scp->clients);
	int i;
	for (i=0; i<scp->clients; i++)
		if (scp->rb->read_client[i]!=-1) sem_post(&scp->rb->sem_empty[i]);

	int exited=0;
	while (exited!=scp->clients) {
		exited=0;
		for (i=0; i<scp->clients; i++) {
			if (scp->rb->read_client[i]==-1) exited++;
		}
		sleep(1);
	}
	printf("%d clients have been exited\n",scp->clients);
	ShareCapMasterRemovePackets(scp);
	/* */

	printf("----------------\n");
	printf("final master sharecap process results:\n");
	ShareCapPrintInfo(scp);
	printf("----------------\n");

	if (p) {
		pcap_breakloop(p);
		pcap_close(p);
	}
	ShareCapRemoveProcess(scp);
	exit(EXIT_SUCCESS);
}

void print_usage(char *prog) {
	printf("usage: %s [OPTIONS]\n",prog);
	printf("  -i, --interface                   Interface name to read packets from\n");
	printf("  -f, --file                        PCAP file to read packets from\n");
	printf("  -c, --clients                     Number of clients (default: 2)\n");
	printf("  -r, --stats-period                Reporting stats period in seconds (default: 10 seconds)\n");
	printf("  -h, --help                        Display this message\n");
}

void packet_header_convert(struct pcap_pkthdr *pkthdr, PacketHeader *hdr) {
	hdr->ts_sec=(uint32_t)pkthdr->ts.tv_sec;
	hdr->ts_usec=(uint32_t)pkthdr->ts.tv_usec;
	hdr->incl_len=(uint32_t)pkthdr->caplen;
	hdr->orig_len=(uint32_t)pkthdr->len;
}

int main(int argc, char **argv) {
	int clients=2;
	int stats_period=10;
	char *file=NULL;
	char *interface=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	int opt;
	static const char optstring[] = "hc:r:i:f:";
	static const struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},
		{"file", required_argument, NULL, 'f'},
		{"clients", required_argument, NULL, 'c'},
		{"stats-period", required_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	opterr=0;
	while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (opt) {
			case 'r':
				if (optarg) stats_period=atoi(optarg);
			case 'c':
				if (optarg) clients=atoi(optarg);
				break;
			case 'i':
				if (optarg) interface=strdup(optarg);
				break;
			case 'f':
				if (optarg) file=strdup(optarg);
				break;
			case 'h':
			case '?':
			default:
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
		}
	}

	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGINT, terminate);
	signal(SIGKILL, terminate);

	if (clients<=0) {
		printf("no clients - exiting\n");
		exit(EXIT_FAILURE);
	}
	if (!file && !interface) {
		printf("You need to provide either interface or file to read packets from - exiting\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("ShareCap master configured with %d clients\n",clients);
	if (file) printf("Reading packets from %s file\n",file);
	else printf("Reading packets from %s interface\n",interface);

	SetShmSegmentMaxSize(2147483648);
	scp=ShareCapInitMasterProcess(0, 0, clients);
	if (!scp) {
		printf("cannot initialize shared memory - exiting\n");
		exit(EXIT_FAILURE);
	}

	/* remove this part in different case */
	printf("waiting %d clients to start:\n",clients);
	int connected=0, i;
	while (connected!=clients) {
		connected=0;
		for (i=0; i<clients; i++) {
			if (scp->rb->read_client[i]==0) connected++;
		}
		sleep(1);
	}
	printf("%d clients have been started\n",clients);	
	/* */

	if (file) {
		p=pcap_open_offline(file, errbuf);
		if (!p) {
			printf("error opening pcap file %s: %s\n",file,errbuf);
			terminate(0);
		}
	}
	else {
		p=pcap_create(interface, errbuf);
		if (!p) {
			printf("error opening interface %s: %s\n",interface,errbuf);
			terminate(0);
		}
		pcap_set_snaplen(p, 65535);
		pcap_set_promisc(p, 1);
		pcap_set_timeout(p, 100);
		pcap_set_buffer_size(p, 16777216);
		if (pcap_activate(p)) {
			printf("interface %s cannot be activated\n",interface);
			terminate(0);
		}
	}

	Packet pkt;
	PacketHeader hdr;
	pkt.hdr=&hdr;
	struct pcap_pkthdr pkthdr;
	struct timeval tv, last_stats;
	gettimeofday(&last_stats, NULL);

	while (1) {
		pkt.pkt=(u_char*)pcap_next(p, &pkthdr);

		if (pkt.pkt) {
			packet_header_convert(&pkthdr, pkt.hdr);
			ShareCapMasterPutPacket(scp, &pkt, true);
		}
		else if (file) {
			printf("master reached end of pcap file %s - exiting\n",file);
			break;
		}

		gettimeofday(&tv, NULL);
		if (tv.tv_sec-last_stats.tv_sec>(time_t)stats_period) {
			printf("----------------\n");
			ShareCapPrintInfo(scp);
			printf("----------------\n");
			last_stats=tv;
		}
	}

	terminate(0);

	return 0;
}

