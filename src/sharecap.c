/*
Sharing packets among different processes or threads.
Single Producer Multiple Consumer (SPMC):
- one packet producer process/thread that reads packets from interfaces or files and copies in shared memory
- multiple packet consumer processes/threads that read packets from shared memory and process them
apapadog@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>
#include "sharecap.h"


/* Dummy ShareCap filenames and interfaces */

void CreateDummyFilenames(int pool_id, int clients) {
	int i, fd;
	char filename[64];
	mkdir("/tmp/sharecap",0644);
	for (i=0; i<clients; i++) {
		snprintf(filename, 64, "/tmp/sharecap/sharecap-%d-%d",pool_id, i);
		fd=creat(filename, 0644);
		if (fd!=-1) close(fd);
	}
}

void DeleteDummyFilenames(int pool_id, int clients) {
	int i;
	char filename[64];
	for (i=0; i<clients; i++) {
		snprintf(filename, 64, "/tmp/sharecap/sharecap-%d-%d",pool_id, i);
		unlink(filename);
	}
	rmdir("/tmp/sharecap");
}

void CreateDummyInterfaces(int pool_id, int clients) {
	int i;
	char command[128];
	for (i=0; i<clients; i++) {
		snprintf(command, 128, "/sbin/ip li add sharecap-%d-%d type dummy; ifconfig sharecap-%d-%d 0 up mtu 65535",pool_id, i, pool_id, i);
		if (system(command)==-1) { }
	}
}

void DeleteDummyInterfaces(int pool_id, int clients) {
	int i;
	char command[128];
	for (i=0; i<clients; i++) {
		snprintf(command, 128, "ifconfig sharecap-%d-%d down; /sbin/ip li delete sharecap-%d-%d",pool_id, i, pool_id, i);
		if (system(command)==-1) { }
	}
}

/* end of dummy ShareCap filenames and interfaces */


/* ShmSegment: manage shared memory segments */

ShmSegment *InitShmSegment(bool master, char *name, uint64_t size) {
	if (!name || size==0) return NULL;
	ShmSegment *shm=(ShmSegment*)malloc(sizeof(ShmSegment));
	if (!shm) return NULL;
	shm->master=master;
	shm->name=strdup(name);
	shm->size=size;
	if (master) shm->fd=shm_open(shm->name, O_RDWR | O_CREAT | O_EXCL, S_IROTH | S_IWOTH);
	else shm->fd=shm_open(shm->name, O_RDWR, S_IROTH | S_IWOTH);
	if (shm->fd<0) {
		fprintf(stderr, "InitShmSegment error: cannot %s shared memory segment %s - %s\n",shm->master?"create":"attach", shm->name, errno==EEXIST?"shared memory segment name already exists":errno==ENOENT?"shared memory segment name does not exist":"unexpected error");
		if (shm->name) free(shm->name);
		free(shm);
		return NULL;
	}
	if (ftruncate(shm->fd, shm->size)<0) {
		fprintf(stderr, "InitShmSegment error: cannot set size for shared memory segment %s\n",shm->name);
		if (shm->name) free(shm->name);
		free(shm);
		return NULL;
	}
	shm->addr=mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->fd, 0);
	if (!shm->addr) {
		fprintf(stderr, "InitShmSegment error: cannot mmap shared memory segment %s\n",shm->name);
		if (shm->name) free(shm->name);
		free(shm);
		return NULL;
	}
	fprintf(stderr, "InitShmSegment info: %s shared memory segment %s\n",shm->master?"created":"attached", shm->name);
	return shm;
}

void CleanupShmSegment(ShmSegment *shm) {
	if (!shm) return;
	close(shm->fd);
	if (shm->addr) munmap(shm->addr, shm->size);
	if (shm->master && shm->name) shm_unlink(shm->name);
	fprintf(stderr, "CleanupShmSegment info: %s shared memory segment %s\n",shm->master?"deleted":"detached", shm->name);	
	if (shm->name) free(shm->name);
	free(shm);
}

/* end of ShmSegment */


/* ShmRingBuffer: Ring Buffer in Shared Memory */

void InitShmRingBuffer(ShmRingBuffer *rb, uint64_t size) {
	if (!rb || size==0) return;
	rb->size=size;
	rb->used=0;
	rb->write=0;
	rb->read=0;
	rb->rewind=rb->size;
	sem_init(&rb->sem_full, 1, 0);
	rb->is_full=0;
	int i;
	for (i=0; i<MAX_CLIENTS; i++) {
		rb->read_client[i]=(uint64_t)-1;
		sem_init(&rb->sem_empty[i], 1, 0);
	}
	fprintf(stderr, "InitShmRingBuffer info: shm ring buffer initialized\n");
}

void CleanupShmRingBuffer(ShmRingBuffer *rb) {
	if (!rb) return;
	sem_destroy(&rb->sem_full);
	int i;
	for (i=0; i<MAX_CLIENTS; i++)
		sem_destroy(&rb->sem_empty[i]);
	fprintf(stderr, "CleanupShmRingBuffer info: shm ring buffer cleaned up\n");
}

void SetShmSegmentMaxSize(uint64_t bytes) {
	if (bytes==0) bytes=8589934592;		//default
	if (bytes%sysconf(_SC_PAGESIZE)!=0) bytes=((bytes/sysconf(_SC_PAGESIZE))+1)*sysconf(_SC_PAGESIZE);	//multiple of page size
	uint64_t pages=bytes/sysconf(_SC_PAGESIZE);
	char sysctl_command[128];
	snprintf(sysctl_command, 128, "if [ %lu -gt `sysctl -n kernel.shmall` ]; then sysctl -w kernel.shmall=%lu; fi",pages, pages);
	if (system(sysctl_command)!=0) fprintf(stderr, "SetShmSegmentMaxSize warning: cannot change kernel.shmall to %lu pages\n",pages);
	else fprintf(stderr, "SetShmSegmentMaxSize info: changed kernel.shmall to %lu pages (%lu bytes)\n",pages, bytes);
	snprintf(sysctl_command, 128, "if [ %lu -gt `sysctl -n kernel.shmmax` ]; then sysctl -w kernel.shmmax=%lu; fi",bytes, bytes);
	if (system(sysctl_command)!=0) fprintf(stderr, "SetShmSegmentMaxSize warning: cannot change kernel.shmmax to %lu bytes\n",bytes);
	else fprintf(stderr, "SetShmSegmentMaxSize info: changed kernel.shmmax to %lu bytes (%lu pages)\n",bytes, pages);
}

/* end of ShmRingBuffer */


/* ShareCapProcess: One master process/thread and multiple client processes/threads */

ShareCapProcess *ShareCapInitProcessCommon(bool master, int pool_id, uint64_t buffer_size, int client_id, int clients, ShareCapProcess *copy_segments) {
	char shm_name[128];
	ShareCapProcess *scp=(ShareCapProcess*)malloc(sizeof(ShareCapProcess));
	if (!scp) return NULL;
	scp->master=master;
	scp->zero=0;
	scp->breakloop=0;
	scp->end_of_file=0;
	scp->do_not_free=0;

	if (pool_id<0) pool_id=0;
	scp->pool_id=pool_id;

	if (scp->master) {
		if (buffer_size<sysconf(_SC_PAGESIZE)) buffer_size=DEFAULT_SHM_MEM_POOL_SIZE;
		if (buffer_size%sysconf(_SC_PAGESIZE)!=0) buffer_size=((buffer_size/sysconf(_SC_PAGESIZE))+1)*sysconf(_SC_PAGESIZE);	//multiple of page size
		scp->buffer_size=buffer_size;
		scp->clients=clients;
		scp->client_id=-1;
	}
	else {
		scp->clients=-1;
		scp->client_id=client_id;
	}

	if (copy_segments && copy_segments->rb && copy_segments->buff) {
		scp->shm_rb=NULL;
		scp->rb=copy_segments->rb;
	}
	else {
		snprintf(shm_name, 128, "sharecap-shm-ring-buffer-%d", scp->pool_id);
		scp->shm_rb=InitShmSegment(master, shm_name, sizeof(ShmRingBuffer));
		if (scp->shm_rb==NULL) {
			fprintf(stderr, "ShareCapInitProcessCommon error: cannot initialize %s process (pid: %d tid: %ld) with %s %d in the process pool %d - cannot %s ring buffer shared memory segment\n",scp->master?"master":"client", (int)getpid(), syscall(SYS_gettid), scp->master?"clients":"client id", scp->master?scp->clients:scp->client_id, scp->pool_id, scp->master?"create":"attach");
			free(scp);
			return NULL;
		}
		scp->rb=(ShmRingBuffer*)scp->shm_rb->addr;
		if (master) InitShmRingBuffer(scp->rb, scp->buffer_size);
	}

	if (!master) {
		scp->buffer_size=scp->rb->size;
		if (scp->rb->read_client[scp->client_id]!=-1) {
			fprintf(stderr, "ShareCapInitProcessCommon error: cannot initialize client process (pid: %d tid: %ld) with client id %d in the process pool %d - client process with cliend id %d already running on this process pool\n",(int)getpid(), syscall(SYS_gettid), scp->client_id, scp->pool_id, scp->client_id);
			if (scp->shm_rb) CleanupShmSegment(scp->shm_rb);
			free(scp);
			return NULL;
		}
		scp->rb->read_client[client_id]=0;
	}

	if (copy_segments && copy_segments->rb && copy_segments->buff) {
		scp->shm_buff=NULL;
		scp->buff=copy_segments->buff;
	}
	else {
		snprintf(shm_name, 128, "sharecap-shm-mem-pool-%d", scp->pool_id);
		scp->shm_buff=InitShmSegment(master, shm_name, scp->buffer_size);
		if (scp->shm_buff==NULL) {
			fprintf(stderr, "ShareCapInitProcessCommon error: cannot initialize %s process (pid: %d tid: %ld) with %s %d in the process pool %d with %lu buffer size - cannot %s memory pool shared memory segment\n",scp->master?"master":"client", (int)getpid(), syscall(SYS_gettid), scp->master?"clients":"client id", scp->master?scp->clients:scp->client_id, scp->pool_id, scp->buffer_size, scp->master?"create":"attach");
			if (scp->shm_rb) CleanupShmSegment(scp->shm_rb);
			free(scp);
			return NULL;
		}
		scp->buff=(u_char*)scp->shm_buff->addr;
	}

	if (master) {
		CreateDummyFilenames(scp->pool_id, scp->clients);
		CreateDummyInterfaces(scp->pool_id, scp->clients);
	}

	memset(&scp->pkt, 0, sizeof(Packet));
	memset(&scp->stats, 0, sizeof(ShareCapProcessStats));
	fprintf(stderr, "ShareCapInitProcessCommon info: initialized %s process (pid: %d tid: %ld) with %s %d in the process pool %d with %lu buffer size\n",scp->master?"master":"client", (int)getpid(), syscall(SYS_gettid), scp->master?"clients":"client id", scp->master?scp->clients:scp->client_id, scp->pool_id, scp->buffer_size);
	return scp;
}

ShareCapProcess *ShareCapInitMasterProcess(int pool_id, uint64_t buffer_size, int clients) {
	if (clients<=0 || clients>MAX_CLIENTS) clients=2;
	return ShareCapInitProcessCommon(true, pool_id, buffer_size, -1, clients, NULL);
}

ShareCapProcess *ShareCapInitClientProcess(int pool_id, int client_id, ShareCapProcess *copy_segments) {
	if (client_id<0 || client_id>=MAX_CLIENTS) return NULL;
	return ShareCapInitProcessCommon(false, pool_id, 0, client_id, -1, copy_segments);
}

void ShareCapRemoveProcess(ShareCapProcess *scp) {
	if (!scp) return;
	if (!scp->master) {
		//sem_post(&scp->rb->sem_empty[scp->client_id]);
		if (scp->rb) scp->rb->read_client[scp->client_id]=(uint64_t)-1;
	}
	else {
		//scp->rb->is_full=0;
		//sem_post(&scp->rb->sem_full);
		CleanupShmRingBuffer(scp->rb);
		DeleteDummyFilenames(scp->pool_id, scp->clients);
		DeleteDummyInterfaces(scp->pool_id, scp->clients);
	}
	if (scp->shm_rb) CleanupShmSegment(scp->shm_rb);
	if (scp->shm_buff) CleanupShmSegment(scp->shm_buff);
	fprintf(stderr, "ShareCapRemoveProcess info: removed %s process (pid: %d tid: %ld) with %s %d from process pool %d\n",scp->master?"master":"client", (int)getpid(), syscall(SYS_gettid), scp->master?"clients":"client id", scp->master?scp->clients:scp->client_id, scp->pool_id);
	if (scp->do_not_free==0) free(scp);
}

/* end of ShareCapProcess */


/* ring buffer functions: */

bool ShareCapMasterPutPacket(ShareCapProcess *scp, Packet *pkt, bool blocking) {
	if (!scp || !scp->master || !scp->rb || !pkt || !pkt->hdr || !pkt->pkt) return false;

	uint64_t bytes_required=sizeof(PacketHeader)+pkt->hdr->incl_len;

	bool space_available=false;
	while (!space_available) {
		if (blocking) scp->rb->is_full=1;		//in case buffer is full
		ShareCapMasterRemovePackets(scp);		//remove processed packets to make space for new ones
		space_available=ShareCapMasterHasFreeBytesContiguous(scp, bytes_required);
		if (!space_available) {
			if (!blocking) return false;
			sem_wait(&scp->rb->sem_full);
		}
	}

	if (blocking) scp->rb->is_full=0;

	//copy packet data to shm memory pool
	memcpy(scp->buff+scp->rb->write, pkt->hdr, sizeof(PacketHeader));
	memcpy(scp->buff+scp->rb->write+sizeof(PacketHeader), pkt->pkt, pkt->hdr->incl_len);

	scp->rb->used+=bytes_required;
	scp->rb->write=(scp->rb->write+bytes_required)%scp->rb->size;
	int i;
	for (i=0; i<scp->clients; i++)
		sem_post(&scp->rb->sem_empty[i]);

	scp->stats.pkts++;
	scp->stats.bytes+=pkt->hdr->incl_len;

	return true;
}

Packet *ShareCapClientGetPacket(ShareCapProcess *scp, bool blocking) {
	if (!scp || scp->master || !scp->rb) return NULL;

	if (!blocking && scp->rb->read_client[scp->client_id]==scp->rb->write && scp->rb->used!=scp->rb->size) return NULL;
	if (scp->rb->read_client[scp->client_id]==scp->rb->rewind) scp->rb->read_client[scp->client_id]=0;	//rewind
	if (!blocking && scp->rb->read_client[scp->client_id]==scp->rb->write && scp->rb->used!=scp->rb->size) return NULL;
	if (blocking) {
		sem_wait(&scp->rb->sem_empty[scp->client_id]);
		if (scp->rb->read_client[scp->client_id]==scp->rb->write && scp->rb->used!=scp->rb->size) return NULL;
	}

	scp->pkt.hdr=(PacketHeader*)(scp->buff+scp->rb->read_client[scp->client_id]);
	scp->pkt.pkt=scp->buff+scp->rb->read_client[scp->client_id]+sizeof(PacketHeader);

	return &scp->pkt;
}

bool ShareCapClientReleasePacket(ShareCapProcess *scp) {
	if (!scp || scp->master || !scp->rb) return false;

	if (scp->rb->read_client[scp->client_id]!=scp->rb->write || scp->rb->used==scp->rb->size) {
		scp->stats.pkts++;
		scp->stats.bytes+=((PacketHeader*)(scp->buff+scp->rb->read_client[scp->client_id]))->incl_len;

		uint64_t bytes_read=sizeof(PacketHeader)+((PacketHeader*)(scp->buff+scp->rb->read_client[scp->client_id]))->incl_len;
		scp->rb->read_client[scp->client_id]=(scp->rb->read_client[scp->client_id]+bytes_read)%scp->rb->size;

		if (scp->rb->is_full==1) {
			scp->rb->is_full=0;
			sem_post(&scp->rb->sem_full);
		}
	}

	return true;
}

//help functions:

bool ShareCapMasterRemovePackets(ShareCapProcess *scp) {
	if (!scp || !scp->master || !scp->rb) return false;
	uint64_t last_read=ShareCapMasterLastReadClient(scp);
	if (last_read!=(uint64_t)-1 && last_read!=scp->rb->read) {
		if (last_read>scp->rb->read) scp->rb->used-=last_read-scp->rb->read;
		else scp->rb->used-=(scp->rb->rewind-scp->rb->read)+last_read;
		scp->rb->read=last_read;
		return true;
	}
	return false;
}

bool ShareCapMasterHasFreeBytesContiguous(ShareCapProcess *scp, uint64_t bytes_needed) {
	if (!ShareCapMasterHasFreeBytes(scp, bytes_needed)) return false;

	if (scp->rb->write>=scp->rb->read && scp->rb->size-scp->rb->write>=bytes_needed) return true;
	else if (scp->rb->write>=scp->rb->read && scp->rb->read>=bytes_needed) {
		uint64_t write=scp->rb->write;
		scp->rb->write=0;
		scp->rb->rewind=write;
		return true;
        }
        else if (scp->rb->write<scp->rb->read && scp->rb->read-scp->rb->write>=bytes_needed) return true;
	return false;
}

#define ShmRingBufferDistance(read_client, write, used, size) ((write==read_client)?(used==size?size:0):(write>=read_client?write-read_client:size-read_client+write))
//#define ShmRingBufferDistance(read_client, write, used, size, rewind) ((write==read_client)?(used==size?size:0):(write>=read_client?write-read_client:rewind-read_client+write))

uint64_t ShareCapMasterLastReadClient(ShareCapProcess *scp) {
	if (!scp || !scp->master || !scp->rb) return (uint64_t)-1;
	uint64_t last_read_client, read_client;
	uint64_t max_distance, distance;
	int i;
	last_read_client=scp->rb->read_client[0];
	max_distance=0;
	for (i=0; i<scp->clients; i++) {
		read_client=scp->rb->read_client[i];
		if (read_client==(uint64_t)-1) continue;
		distance=ShmRingBufferDistance(read_client, scp->rb->write, scp->rb->used, scp->rb->size);
		if (distance>max_distance) {
			max_distance=distance;
			last_read_client=read_client;
		}
	}
	return last_read_client;
}

void ShareCapPrintInfo(ShareCapProcess *scp) {
	if (!scp || !scp->rb) return;
	if (scp->master) fprintf(stderr, "ShareCap master info: process pool: %d  clients: %d  shared: %lu packets %lu bytes\n",scp->pool_id, scp->clients, scp->stats.pkts, scp->stats.bytes);
	else fprintf(stderr, "ShareCap client info: process pool: %d  client id: %d  processed: %lu packets %lu bytes\n",scp->pool_id, scp->client_id, scp->stats.pkts, scp->stats.bytes);
	fprintf(stderr, "ShareCap shm ring buffer info: size: %lu used: %lu usage: %.3lf\n",scp->rb->size, scp->rb->used, (double)scp->rb->used/(double)scp->rb->size*100.0);
}

/* end of ring buffer functions */


/* master and client loop */

void ShareCapMasterLoop(int pool_id, uint64_t buffer_size, int clients, Packet* (*GetNextPacket) (void *), void *user) {
	if (clients<=0 || !GetNextPacket) return;

	//SetShmSegmentMaxSize(2147483648);
	ShareCapProcess *scp=ShareCapInitMasterProcess(pool_id, buffer_size, clients);
	while (1) {
		ShareCapMasterPutPacket(scp, GetNextPacket(user), true);
	}
	ShareCapRemoveProcess(scp);
}

void ShareCapClientLoop(int pool_id, uint64_t buffer_size, int client_id, void (*ProcessNextPacket) (void *, Packet*), void *user) {
	if (client_id<0 || client_id>=MAX_CLIENTS || !ProcessNextPacket) return;

	ShareCapProcess *scp=ShareCapInitClientProcess(pool_id, client_id, NULL);
	while (1) {
		Packet *pkt=ShareCapClientGetPacket(scp, true);
		if (pkt && pkt->pkt && pkt->hdr) {
			ProcessNextPacket(user, pkt);
			ShareCapClientReleasePacket(scp);
		}
		else break;
	}
	ShareCapRemoveProcess(scp);
}

void ShareCapMasterWaitClientsStart(ShareCapProcess *scp) {
	if (!scp) return;

	fprintf(stderr,"ShareCapMasterWaitClients info: waiting %d clients to start:\n",scp->clients);
	int connected=0, i;
	while (connected!=scp->clients) {
		connected=0;
		for (i=0; i<scp->clients; i++) {
			if (scp->rb->read_client[i]==0) connected++;
		}
		if (connected!=scp->clients) usleep(100);
	}
	fprintf(stderr,"ShareCapMasterWaitClients info: %d clients have been started\n",scp->clients);
}

void ShareCapMasterWaitClientsExit(ShareCapProcess *scp) {
	if (!scp) return;

	usleep(100);
	ShareCapMasterRemovePackets(scp);

	fprintf(stderr,"ShareCapMasterWaitClientsExit info: waiting %d clients to exit:\n",scp->clients);
	int i;
//	for (i=0; i<scp->clients; i++)
//		if (scp->rb->read_client[i]!=-1) sem_post(&scp->rb->sem_empty[i]);

	int exited=0;
	while (exited!=scp->clients) {
		exited=0;
		for (i=0; i<scp->clients; i++) {
			if (scp->rb->read_client[i]==-1) exited++;
		}
		if (exited!=scp->clients) usleep(100);
	}
	fprintf(stderr,"ShareCapMasterWaitClientsExit info: %d clients have been exited\n",scp->clients);
	ShareCapMasterRemovePackets(scp);
}

/* end of master and client loop */


