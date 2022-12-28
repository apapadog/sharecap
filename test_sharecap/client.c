#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
uint64_t pkts=0, bytes=0;

void terminate(int signal) {
	if (!scp) exit(EXIT_SUCCESS);
	printf("----------------\n");
	printf("final client %d sharecap process results:\n",scp->client_id);
	printf("client %d processed: %lu pkts, %lu bytes\n",scp->client_id, pkts, bytes);
	ShareCapPrintInfo(scp);
	printf("----------------\n");
	ShareCapRemoveProcess(scp);
	exit(EXIT_SUCCESS);
}

void print_usage(char *prog) {
	printf("usage: %s [OPTIONS]\n",prog);
	printf("  -c, --client-id                   Number of clients (default: 2)\n");
	printf("  -r, --stats-period                Reporting stats period in seconds (default: 10 seconds)\n");
	printf("  -h, --help                        Display this message\n");
}

int main(int argc, char **argv) {
	int client_id=-1;
	int stats_period=10;

	int opt;
	static const char optstring[] = "hc:r:";
	static const struct option longopts[] = {
		{"client-id", required_argument, NULL, 'c'},
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
				if (optarg) client_id=atoi(optarg);
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

	if (client_id<0 || client_id>=MAX_CLIENTS) {
		printf("You need to provide a valid client id - exiting\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("ShareCap client process with client id: %d\n",client_id);

	scp=ShareCapInitClientProcess(0, client_id, NULL);
	if (!scp) {
		printf("cannot initialize shared memory - exiting\n");
		exit(EXIT_FAILURE);
	}

	Packet *pkt;
	struct timeval tv, last_stats;
	gettimeofday(&last_stats, NULL);	

	while (1) {
		pkt=ShareCapClientGetPacket(scp, true);
		if (pkt && pkt->pkt && pkt->hdr) {
			pkts++;
			bytes+=pkt->hdr->orig_len;
			ShareCapClientReleasePacket(scp);
		}
		else {
			printf("master is exiting - exiting client %d\n",client_id);
			break;
		}

		gettimeofday(&tv, NULL);
		if (tv.tv_sec-last_stats.tv_sec>(time_t)stats_period) {
			printf("----------------\n");
			printf("client %d processed: %lu pkts, %lu bytes\n",client_id, pkts, bytes);
			ShareCapPrintInfo(scp);
			printf("----------------\n");
			last_stats=tv;
		}
	}

	terminate(0);

	return 0;
}

