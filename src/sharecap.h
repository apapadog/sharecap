/*
Sharing packets among different processes or threads.
Single Producer Multiple Consumer (SPMC):
- one packet producer process/thread that reads packets from interfaces or files and copies in shared memory
- multiple packet consumer processes/threads that read packets from shared memory and process them
apapadog@gmail.com
*/

#ifndef _SHARECAP_H_
#define _SHARECAP_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <semaphore.h>

/* Packet structs */

typedef struct __attribute__((__packed__)) _PacketHeader {
	uint32_t ts_sec;		// timestamp seconds
	uint32_t ts_usec;		// timestamp microseconds
	uint32_t incl_len;		// included length of this packet
	uint32_t orig_len;		// original length of this packet
} PacketHeader;

typedef struct __attribute__((__packed__)) _Packet {
	PacketHeader *hdr;
	u_char *pkt;
} Packet;

/* end of Packet structs*/


/* Dummy ShareCap filenames and interfaces */

void CreateDummyFilenames(int pool_id, int clients);
void CreateDummyInterfaces(int pool_id, int clients);
void DeleteDummyFilenames(int pool_id, int clients);
void DeleteDummyInterfaces(int pool_id, int clients);

/* end of dummy ShareCap filenames and interfaces */


/* ShmSegment: manage shared memory segments */

typedef struct _ShmSegment {
	bool master;
	char *name;
	uint64_t size;
	int fd;
	void *addr;
} ShmSegment;

ShmSegment *InitShmSegment(bool master, char *name, uint64_t size);
void CleanupShmSegment(ShmSegment *shm);
void SetShmSegmentMaxSize(uint64_t bytes);

/* end of ShmSegment */


/* ShmRingBuffer: Ring Buffer in Shared Memory */

#define MAX_CLIENTS 16

typedef struct __attribute__((__packed__)) _ShmRingBuffer {
	//master fields
	uint64_t size;
	uint64_t used;
	uint64_t write;
	uint64_t read;
	uint64_t rewind;
	sem_t sem_full;
	int is_full;
	//client fields
	uint64_t read_client[MAX_CLIENTS];
	sem_t sem_empty[MAX_CLIENTS];
} ShmRingBuffer;

void InitShmRingBuffer(ShmRingBuffer *rb, uint64_t size);
void CleanupShmRingBuffer(ShmRingBuffer *rb);

/* end of ShmRingBuffer */


/* ShareCapProcess: One master process/thread and multiple client processes/threads */

#define DEFAULT_SHM_MEM_POOL_SIZE 1073741824	//262144 pages (page size 4096)

typedef struct _ShareCapProcessStats {
	uint64_t pkts;
	uint64_t bytes;
} ShareCapProcessStats;

typedef struct _ShareCapProcess {
	uint64_t zero;
	bool master;
	int pool_id;
	uint64_t buffer_size;
	int clients;		//for master
	int client_id;		//for clients
	ShmSegment *shm_rb;
	ShmSegment *shm_buff;
	ShmRingBuffer *rb;
	u_char *buff;
	Packet pkt;
	ShareCapProcessStats stats;
	int breakloop;
	int end_of_file;
	int do_not_free;
} ShareCapProcess;

ShareCapProcess *ShareCapInitMasterProcess(int pool_id, uint64_t buffer_size, int clients);
ShareCapProcess *ShareCapInitClientProcess(int pool_id, int client_id, ShareCapProcess *copy_segments);
void ShareCapRemoveProcess(ShareCapProcess *scp);

/* end of ShareCapProces */ 


/* ring buffer functions: */

bool ShareCapMasterPutPacket(ShareCapProcess *scp, Packet *pkt, bool blocking);
Packet *ShareCapClientGetPacket(ShareCapProcess *scp, bool blocking);
bool ShareCapClientReleasePacket(ShareCapProcess *scp);

//help functions:
bool ShareCapMasterRemovePackets(ShareCapProcess *scp);
uint64_t ShareCapMasterLastReadClient(ShareCapProcess *scp);
bool ShareCapMasterHasFreeBytesContiguous(ShareCapProcess *scp, uint64_t bytes_needed);

#define ShareCapMasterIsEmpty(scp) (scp && scp->master && scp->rb && scp->rb->used==0)
#define ShareCapMasterIsFull(scp) (scp && scp->master && scp->rb && scp->rb->used==scp->rb->size)
#define ShareCapMasterHasFreeBytes(scp, bytes_needed) (scp && scp->master && scp->rb && scp->rb->size-scp->rb->used>=bytes_needed)
#define ShareCapMasterUsedBytes(scp) ((scp && scp->master && scp->rb)?scp->rb->used:0)
#define ShareCapMasterBufferUsage(scp) ((scp && scp->master && scp->rb && scp->rb->size>0)?((double)scp->rb->used/(double)scp->rb->size*100.0):0)

#define ShareCapClientHasDataToRead(scp) (scp && !scp->master && scp->rb && (scp->rb->read_client[scp->client_id]!=scp->rb->write || scp->rb->used==scp->rb->size))

#define ShareCapBufferSize(scp) ((scp && scp->rb)?scp->rb->size:0)

void ShareCapPrintInfo(ShareCapProcess *scp);

/* end of ring buffer functions */


/* master and client loop */

void ShareCapMasterLoop(int pool_id, uint64_t buffer_size, int clients, Packet* (*GetNextPacket) (void *), void *user);
void ShareCapClientLoop(int pool_id, uint64_t buffer_size, int client_id, void (*ProcessNextPacket) (void *, Packet*), void *user);

void ShareCapMasterWaitClientsStart(ShareCapProcess *scp);
void ShareCapMasterWaitClientsExit(ShareCapProcess *scp);

/* end of master and client loop */

#endif /* _SHARECAP_H_ */
