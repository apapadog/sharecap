/*
 * libpcap wrapper for sharecap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <pcap.h>
#include <sys/time.h>
#include <unistd.h>
#include "../src/sharecap.h"


/* help functions */

bool IsShareCapProccess(void *ptr) {
	if (ptr && ((ShareCapProcess*)ptr)->zero==0) return true;
	else return false;
}

ShareCapProcess *InitShareCapWrapper(char *name, char *errbuf) {
	if (!name) return NULL;

	int client_id=-1, pool_id=-1;
	char *token;
	token=strtok(name, "-");
	token=strtok(NULL, "-");
	if (token) pool_id=atoi(token);
	token=strtok(NULL, "-");
	if (token) client_id=atoi(token);

	if (pool_id<0) pool_id=-1;
	if (client_id<0 || client_id>=MAX_CLIENTS) client_id=-1;

	if (pool_id==-1 || client_id==-1) {
		fprintf(stderr, "Cannot initialize ShareCap: invalid pool_id or client_id in the name string\n");
		if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "Cannot initialize ShareCap: invalid pool_id or client_id in the name string");
		return NULL;
	}
	fprintf(stderr, "Initializing ShareCap with pool_id: %d and client_id: %d\n",pool_id, client_id);

	ShareCapProcess *scp=ShareCapInitClientProcess(pool_id, client_id, NULL);
	if (!scp) {
		fprintf(stderr, "Cannot initialize ShareCap\n");
		if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "Cannot initialize ShareCap");
		return NULL;
	}
	fprintf(stderr, "Initialized ShareCap with pool_id: %d and client_id: %d\n",pool_id, client_id);

	return scp;
}

/* end of help functions */


/* intercepting pcap functions */

pcap_t *pcap_create(const char *device, char *errbuf) {
	fprintf(stderr, "ShareCap pcap_create() wrapper: given device %s\n",device!=NULL?device:"null");
	if (strncmp(device, "sharecap-", 9)==0) {
		fprintf(stderr, "Using ShareCap to get packets\n");
		return (pcap_t*)InitShareCapWrapper((char*)device, errbuf);
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		pcap_t *(*original_pcap_create)(const char *, char *);
		original_pcap_create=dlsym(RTLD_NEXT, "pcap_create");
		return (*original_pcap_create)(device, errbuf);
	}
}

pcap_t *pcap_open_offline(const char *fname, char *errbuf) {
	fprintf(stderr, "ShareCap pcap_open_offline() wrapper: given filename %s\n",fname!=NULL?fname:"null");
	if (strncmp(fname, "/tmp/sharecap/sharecap-", 23)==0) {
		fprintf(stderr, "Using ShareCap to get packets\n");
		return (pcap_t*)InitShareCapWrapper((char*)fname, errbuf);
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		pcap_t *(*original_pcap_open_offline)(const char *, char *);
		original_pcap_open_offline=dlsym(RTLD_NEXT, "pcap_open_offline");
		return (*original_pcap_open_offline)(fname, errbuf);
	}
}

void pcap_close(pcap_t *p) {
	fprintf(stderr, "ShareCap pcap_close() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return;
		ShareCapProcess *scp=(ShareCapProcess*)p;
		if (scp->end_of_file==0) {
			fprintf(stderr, "----------------\n");
			fprintf(stderr, "Closing ShareCap client %d from pool %d\n",scp->client_id, scp->pool_id);
			ShareCapPrintInfo(scp);
			fprintf(stderr, "----------------\n");
			ShareCapRemoveProcess(scp);
		}
		else free(scp);
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		void (*original_pcap_close)(pcap_t *);
		original_pcap_close=dlsym(RTLD_NEXT, "pcap_close");
		return (*original_pcap_close)(p);
	}
}

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
	//fprintf(stderr, "ShareCap pcap_dispatch() wrapper\n");
	if (IsShareCapProccess(p)) {
		//fprintf(stderr, "Using ShareCap\n");
		if (!p || !callback) return -1;
		ShareCapProcess *scp=(ShareCapProcess*)p;
		if (scp->end_of_file==1) return 0;
		int packets=0;
		Packet *pkt;
		scp->breakloop=0;
		while (cnt<=0 || packets<cnt) {
			pkt=ShareCapClientGetPacket(scp, true);
			if (pkt && pkt->pkt && pkt->hdr) {
				struct pcap_pkthdr hdr;
				hdr.caplen=pkt->hdr->incl_len;
				hdr.len=pkt->hdr->orig_len;
				hdr.ts.tv_sec=pkt->hdr->ts_sec;
				hdr.ts.tv_usec=pkt->hdr->ts_usec;
				(*callback)(user, &hdr, pkt->pkt);
				ShareCapClientReleasePacket(scp);
				packets++;
			}
			else {
				fprintf(stderr, "master is exiting - stopping pcap_dispatch() for client %d pool %d\n",scp->client_id, scp->pool_id);
				scp->do_not_free=1;
				fprintf(stderr, "----------------\n");
				fprintf(stderr, "Closing ShareCap client %d from pool %d\n",scp->client_id, scp->pool_id);
				ShareCapPrintInfo(scp);
				fprintf(stderr, "----------------\n");
				ShareCapRemoveProcess(scp);
				scp->do_not_free=0;
				scp->end_of_file=1;
				break;
			}
			if (scp->breakloop==1) break;
		}
		return packets;
	}
	else {
		//fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_dispatch)(pcap_t *, int, pcap_handler, u_char *);
		original_pcap_dispatch=dlsym(RTLD_NEXT, "pcap_dispatch");
		return (*original_pcap_dispatch)(p, cnt, callback, user);
	}
}

int pcap_stats(pcap_t *p, struct pcap_stat *ps) {
	//fprintf(stderr, "ShareCap pcap_stats() wrapper\n");
	if (IsShareCapProccess(p)) {
		//fprintf(stderr, "Using ShareCap\n");
		if (!p || !ps) return -1;
		ShareCapProcess *scp=(ShareCapProcess*)p;
		ps->ps_recv=scp->stats.pkts;
		ps->ps_drop=0;
		ps->ps_ifdrop=0;
		return 0;
	}
	else {
		//fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_stats)(pcap_t *, struct pcap_stat *);
		original_pcap_stats=dlsym(RTLD_NEXT, "pcap_stats");
		return (*original_pcap_stats)(p, ps);
	}
}

int pcap_activate(pcap_t *p) {
	fprintf(stderr, "ShareCap pcap_activate() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return 0;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_activate)(pcap_t *);
		original_pcap_activate=dlsym(RTLD_NEXT, "pcap_activate");
		return (*original_pcap_activate)(p);
	}
}

char *pcap_geterr(pcap_t *p) {
	//fprintf(stderr, "ShareCap pcap_geterr() wrapper\n");
	if (IsShareCapProccess(p)) {
		//fprintf(stderr, "Using ShareCap\n");
		if (!p) return NULL;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return "ShareCap";
	}
	else {
		//fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		char *(*original_pcap_geterr)(pcap_t *);
		original_pcap_geterr=dlsym(RTLD_NEXT, "pcap_geterr");
		return (*original_pcap_geterr)(p);
	}
}

void pcap_breakloop(pcap_t *p) {
	fprintf(stderr, "ShareCap pcap_breakloop() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return;
		ShareCapProcess *scp=(ShareCapProcess*)p;
		scp->breakloop=1;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		void (*original_pcap_breakloop)(pcap_t *);
		original_pcap_breakloop=dlsym(RTLD_NEXT, "pcap_breakloop");
		return (*original_pcap_breakloop)(p);
	}
}

int pcap_set_snaplen(pcap_t *p, int snaplen) {
	fprintf(stderr, "ShareCap pcap_set_snaplen() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return 0;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_set_snaplen)(pcap_t *, int);
		original_pcap_set_snaplen=dlsym(RTLD_NEXT, "pcap_set_snaplen");
		return (*original_pcap_set_snaplen)(p, snaplen);
	}
}

int pcap_set_promisc(pcap_t *p, int promisc) {
	fprintf(stderr, "ShareCap pcap_set_promisc() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return 0;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_set_promisc)(pcap_t *, int);
		original_pcap_set_promisc=dlsym(RTLD_NEXT, "pcap_set_promisc");
		return (*original_pcap_set_promisc)(p, promisc);
	}
}


int pcap_set_timeout(pcap_t *p, int to_ms) {
	fprintf(stderr, "ShareCap pcap_set_timeout() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return 0;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_set_timeout)(pcap_t *, int);
		original_pcap_set_timeout=dlsym(RTLD_NEXT, "pcap_set_timeout");
		return (*original_pcap_set_timeout)(p, to_ms);
	}
}


int pcap_set_buffer_size(pcap_t *p, int buffer_size) {
	fprintf(stderr, "ShareCap pcap_set_buffer_size() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return 0;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_set_buffer_size)(pcap_t *, int);
		original_pcap_set_buffer_size=dlsym(RTLD_NEXT, "pcap_set_buffer_size");
		return (*original_pcap_set_buffer_size)(p, buffer_size);
	}
}

int pcap_datalink(pcap_t *p) {
	fprintf(stderr, "ShareCap pcap_datalink() wrapper\n");
	if (IsShareCapProccess(p)) {
		fprintf(stderr, "Using ShareCap\n");
		if (!p) return -1;
		//ShareCapProcess *scp=(ShareCapProcess*)p;
		return DLT_EN10MB;
	}
	else {
		fprintf(stderr, "ShareCap bypassed - using original libpcap\n");
		int (*original_pcap_datalink)(pcap_t *);
		original_pcap_datalink=dlsym(RTLD_NEXT, "pcap_datalink");
		return (*original_pcap_datalink)(p);
	}
}

//int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
//void pcap_freealldevs(pcap_if_t *alldevs);

//XXX wrap the rest libpcap functions (not being used by suricata currently)
