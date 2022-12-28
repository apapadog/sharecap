Efficient packet sharing among multiple processes/threads
=====

### Sharing packets among different processes or threads

Sharing packets among different processes or threads.
Single Producer Multiple Consumers (SPMC):

- one packet producer process/thread that reads packets from interfaces or files and copies in shared memory
- multiple packet consumer processes/threads that read packets from shared memory and process them

The idea:

There is only a single producer process/thread that adds or removes packets into/from shared memory.
This is called as the **master** process.
Only the master process can write, remove, or change data into the shared memory ring buffer.
Therefore, there is no need for lock (or atomic instructions) to ensure correct operation of the shared-memory ring buffer.

There are multiple consumer processes or threads that only read packets from shared memory.
These are called as **client** processes.
They do not add/remove or change the contents of the ring buffer - they are read only.
They read new data, when added by the master process, based on the **write** index that is updated by the master process after the new data has been copied.
Then, they update their **read** index. There is one dedicated and separate read index per every client process.
Therefore, each client process writes into a separate memory region for its own read index, so no lock (or atomic instruction) is necessary.
The master process knows from initialization how many client processes exist (this is a requirement - we do not support dynamically changing the number of consumers) so it checks the read indexes from all client processes to find out which packets have been processed by all consumers and treat this memory as free region to fill with new packets.

The packets are shared via shared memory segments. There is a ring buffer into shared memory for this reason.
It consists of two memory segments:

- one that has the ring buffer state: ring buffer size, write offset (set only by master) and read offsets (set by each consumer)
- a second big segment that is the memory pool with packet data (header + raw packet) set only by master

The shared memory segments are created and initialized by master and attached by consumers.

Semaphores in shared memory are used for efficiency when the ring buffer is empty or full.


### The ShareCap library native API

The above solution is implemented as a native library called **ShareCap** with the following API:

- `ShareCapProcess` struct keeps all information about the master and clients processes or threads that are sharing packets (master producing and sharing packets, clients processing and then releasing packets)
- `ShareCapProcess *ShareCapInitMasterProcess(int pool_id, uint64_t buffer_size, int clients);` initializes a master process for process pool ***pool_id*** (default is 0) with buffer size ***buffer_size*** (default is 1GB) with **clients** clients (default is 2) and returns the ShareCapProcess struct created
- `ShareCapProcess *ShareCapInitClientProcess(int pool_id, int client_id, ShareCapProcess *copy_segments);` initializes a client process for process pool ***pool_id*** (default is 0) with the ***client_id*** client ID (which has to be unique) and returns the ShareCapProcess struct created - optionally the shared memory segments can be copied from ***copy_segments*** instance instead of memory mapping, when instances belong to the same process (different threads) sharing the same memory address space
- `void ShareCapRemoveProcess(ShareCapProcess *scp);` removes a master or client process ***scp*** from the packet sharing pool, the master de-allocates all shared memory segments and the ring buffer in shared memory
- `void SetShmSegmentMaxSize(uint64_t bytes);` sets system-wide settings for maximum shared memory size and shared memory segment size to ***bytes*** 
- `bool ShareCapMasterPutPacket(ShareCapProcess *scp, Packet *pkt, bool blocking);` is for the master process **scp** to add the packet **pkt** in shared memory and if **blocking** is true it will block if shared memory buffer is full and there is not enough space to accomodate this packet
- `Packet *ShareCapClientGetPacket(ShareCapProcess *scp, bool blocking);` is for client process **scp** to get the next packet **pkt** (returned) from the shared buffer to process it, and if **blocking** is true it will block when buffer is empty and there is no available packet to get yet
- `bool ShareCapClientReleasePacket(ShareCapProcess *scp);` should be called by the client process **scp** when finished processing the last packet in order to release it and make space for other packets (when all clients are done with this packet). After calling this function last packet is not available any more for this client to get, and moving to next packet (if any)
- `void ShareCapPrintInfo(ShareCapProcess *scp);` prints information and stats about the master or client process **scp** and the corresponding ring buffer
- Other functions: `ShareCapMasterIsEmpty(scp)`, `ShareCapMasterIsFull(scp)`, `ShareCapMasterUsedBytes(scp)`, `ShareCapMasterBufferUsage(scp)`, `ShareCapBufferSize(scp)`
- `void ShareCapMasterLoop(int pool_id, uint64_t buffer_size, int clients, Packet* (*GetNextPacket) (void *), void *user);` one sample function for master loop
- `void ShareCapClientLoop(int pool_id, uint64_t buffer_size, int client_id, void (*ProcessNextPacket) (void *, Packet*), void *user);` one sample function for client loop
- `PacketHeader` and `Packet` structs keep packet information for ShareCap

The detailed ShareCap API can be seen in https://github.com/apapadog/sharecap/blob/main/src/sharecap.h

The implementation is at https://github.com/apapadog/sharecap/blob/main/src/sharecap.c and https://github.com/apapadog/sharecap/blob/main/src directory.

Building the library (just run "make" from src/) produces a static library: libsharecap.a
Any program using the ShareCap library (both master and clients programs, if planning to use different processes) should be linked with libsharecap.a and use the API functions as described in sharecap.h


### Ring buffer in shared memory

ShareCap implements a ring buffer located in shared memory.
This is a big simple circular buffer that stores data (not pointers to data) managed by a single producer process or thread (master) and accessed by multiple consumers (clients).

One small shared memory segment keeps information about the ring buffer: size, bytes used, master's write and read pointers, clients' read pointers, semaphores for empty or full ring buffer to implement blocking calls.
A second big shared memory segment is used to store the actual data.

When ring buffer has to wrap around and write a message that doesn't fit at the end of the buffer (not enough space) but fits at the beggining (enough free space) we prefer to write the message (packet header + packet) in contiguous memory so we wrap around the buffer with a little wasted space at the end.
To synchronize read pointers with this behavior, we use a rewind pointer (actually just buffer offset like write and read offsets) that points to the location that buffer rewind happens, so that clients' read offset is rewinded at the same place when reading as happened when writing.

The main functions implemented for the ringbuffer are:
`InitShmRingBuffer`, `CleanupShmRingBuffer`, `ShareCapMasterPutPacket`, `ShareCapMasterRemovePackets`, `ShareCapClientGetPacket`, `ShareCapClientReleasePacket`
and help functions:
`ShareCapMasterHasFreeBytes`, `ShareCapMasterHasFreeBytesContiguous`, `ShareCapMasterIsEmpty`, `ShareCapMasterIsFull`, `ShareCapMasterUsedBytes`, `ShareCapMasterBufferUsage`, `ShareCapBufferSize`, `ShareCapMasterLastReadClient`, `ShareCapClientHasDataToRead`


### The ShareCap test

Simple test using ShareCap with:
- one master process capturing packets through libpcap (from one interface or one file) and sharing through libsharecap, with variable number of clients
- client process reading packets from shared memory and processing them (just dummy processing), ability to run multiple client processes given a client id

All client processes receive the same packets, but from shared memory -- captured only once from the interface or file.
Only one partition for the captured packets used by master (no fanout / single interface).

Located in the https://github.com/apapadog/sharecap/tree/main/test_sharecap directory.

Build with a simple "make", then run ./master -h and ./client -h for instructions:

```
usage: ./master [OPTIONS]
  -i, --interface                   Interface name to read packets from
  -f, --file                        PCAP file to read packets from
  -c, --clients                     Number of clients (default: 2)
  -r, --stats-period                Reporting stats period in seconds (default: 10 seconds)
  -h, --help                        Display this message
```

```
usage: ./client [OPTIONS]
  -c, --client-id                   Number of clients (default: 2)
  -r, --stats-period                Reporting stats period in seconds (default: 10 seconds)
  -h, --help                        Display this message
```

For example:
```
# ./master -f file.pcap
# ./client -c 0
# ./client -c 1
```

This produces the following result:
```
# ./master -f pcaps/smb-small-1.pcap
ShareCap master configured with 2 clients
Reading packets from pcaps/smb-small-1.pcap file
SetShmSegmentMaxSize info: changed kernel.shmall to 524288 pages (2147483648 bytes)
SetShmSegmentMaxSize info: changed kernel.shmmax to 2147483648 bytes (524288 pages)
InitShmSegment info: created shared memory segment sharecap-shm-mem-pool-1GB
InitShmSegment info: created shared memory segment sharecap-shm-ring-buffer
ShareCapInitProcess info: initialized master process (pid: 20210 tid: 20210)
InitShmRingBuffer info: shm ring buffer initialized
waiting 2 clients to start:

2 clients have been started
master reached end of pcap file pcaps/smb-small-1.pcap - exiting
waiting 2 clients to exit:
2 clients have been exited
----------------
final master sharecap process results:
ShareCap master info: clients: 2  shared: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmRingBuffer info: shm ring buffer cleaned up
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer
CleanupShmSegment info: deleted shared memory segment sharecap-shm-mem-pool-1GB
ShareCapRemoveProcess info: removed master process (pid: 20210 tid: 20210)
#

# ./client -c 0
ShareCap client process with client id: 0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-1GB
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer
ShareCapInitProcess info: initialized client process (pid: 20215 tid: 20215)

master is exiting - exiting client 0
----------------
final client 0 sharecap process results:
client 0 processed: 8 pkts, 536 bytes
ShareCap client info: client id: 0  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer
CleanupShmSegment info: deleted shared memory segment sharecap-shm-mem-pool-1GB
ShareCapRemoveProcess info: removed client process (pid: 20215 tid: 20215)
#

# ./client -c 1
ShareCap client process with client id: 1
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-1GB
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer
ShareCapInitProcess info: initialized client process (pid: 20216 tid: 20216)

master is exiting - exiting client 1
----------------
final client 1 sharecap process results:
client 1 processed: 8 pkts, 536 bytes
ShareCap client info: client id: 1  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer
CleanupShmSegment info: deleted shared memory segment sharecap-shm-mem-pool-1GB
ShareCapRemoveProcess info: removed client process (pid: 20216 tid: 20216)
#
```

Extensions:
- Plan to add a test with master and multiple clients on the same process, using different threads.
- Plan to extend this test with a) master reading from multiple interfaces, or b) creating multiple partitions on the master using packet fanout with the FANOUT\_HASH mode.
In both cases, the master process exposes multiple shared memory segments to the clients (one per interface/partition).
This works with multiple ShareCapProcess master instances, one per partition, so with separate shared memory segments and shm ring buffers per partition, and multiple client instances for each client id respectively.


### ShareCap Dummy Filenames and Interfaces

When starting a ShareCap master process, and while it is running, it exposes one dummy filename and one dummy interface name per each client.
This way, some libpcap-based applications using the libpcap wrapper below can use valid filenames or interface names if required (e.g., suricata validates the file or interface exists with separate checks, outside of libpcap function checks that we can overwrite through our wrapper).

The dummy filenames are:
```
/tmp/sharecap/sharecap-<pool_id>-<client_id>
```
and they are just empty files, one per each client expected.

The dummy interface names are:
```
sharecap-<pool_id>-<client_id>
```
and they are dummy interfaces, one per each client expected.

Both ShareCap dummy files and interfaces are created when master process is initialized, and deleted when master process is stopped.

For example:
```
root@papadog-vm:~# ls /tmp/sharecap/
sharecap-0-0  sharecap-0-1  sharecap-0-2  sharecap-0-3
```
```
root@papadog-vm:~# ifconfig
eth0      Link encap:Ethernet  HWaddr 08:00:27:84:b7:38
          inet addr:10.0.2.15  Bcast:10.0.2.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe84:b738/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:53659 errors:0 dropped:0 overruns:0 frame:0
          TX packets:35068 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:3902008 (3.9 MB)  TX bytes:6518666 (6.5 MB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

sharecap-0-0 Link encap:Ethernet  HWaddr ee:cf:ab:15:14:0d
          inet6 addr: fe80::eccf:abff:fe15:140d/64 Scope:Link
          UP BROADCAST RUNNING NOARP  MTU:65535  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:210 (210.0 B)

sharecap-0-1 Link encap:Ethernet  HWaddr 2e:a3:fa:15:06:4f
          inet6 addr: fe80::2ca3:faff:fe15:64f/64 Scope:Link
          UP BROADCAST RUNNING NOARP  MTU:65535  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:210 (210.0 B)

sharecap-0-2 Link encap:Ethernet  HWaddr e2:d0:2c:6a:2c:3b
          inet6 addr: fe80::e0d0:2cff:fe6a:2c3b/64 Scope:Link
          UP BROADCAST RUNNING NOARP  MTU:65535  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:210 (210.0 B)

sharecap-0-3 Link encap:Ethernet  HWaddr 6a:1a:05:3c:e9:26
          inet6 addr: fe80::681a:5ff:fe3c:e926/64 Scope:Link
          UP BROADCAST RUNNING NOARP  MTU:65535  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:210 (210.0 B)

tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00
          inet addr:192.168.251.10  P-t-P:192.168.251.9  Mask:255.255.255.255
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```


### The libpcap wrapper

ShareCap offers a libpcap wrapper to transparently provide support for sharing packets through libpcap API for any libpcap-based program linked with libpcap.

Used for integration with suricata and any other libpcap program/tool.

All the necessary libpcap functions are intercepted to get packets through ShareCap library calls instead of normal libpcap functions.
This happens only if the filename starts with "/tmp/sharecap/sharecap-" or interface name starts with "sharecap-", else the normal libpcap functions are called from the intercepted functions and no change expected.

The filename should be in the following format:
```
/tmp/sharecap/sharecap-<pool_id>-<client_id>
```
The interface name should be in the following format:
```
sharecap-<pool_id>-<client_id>
```

For example, /tmp/sharecap/sharecap-0-0 as dummy pcap filename or sharecap-0-0 as interface name.

The implementation is located in the https://github.com/apapadog/sharecap/tree/main/libpcap directory.

Build with a simple "make" on this directory.

Building the ShareCap's libpcap wrapper produces the **libpcap.so** shared library and every libpcap program should be dynamically linked with this library, e.g. using LD\_PRELOAD at runtime or -Wl,-rpath= at link time, or any other way either at compile time, linking, or at runtime with the system's library path.

There is a test case with suricata located at the https://github.com/apapadog/sharecap/tree/main/test_suricata directory.


### Suricata integration

Located at the https://github.com/apapadog/sharecap/tree/main/test_suricata directory.

Instructions: run the setup\_suricata.sh script to set up suricata for the suricata integration test.

Run suricata with LD\_PRELOAD=../libpcap/libpcap.so to use the ShareCap libpcap wrapper.
For example:

```
LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml -r ../../pcaps/smb-small-1.pcap
```

This runs suricata with ShareCap libpcap wrapper library, but loads directly a normal pcap file (not a "special" sharecap filename).
Therefore, the libpcap wrapper directs all pcap function calls to the original libpcap installed on the system (no ShareCap functionality),
and no change is observed -- besides a few more lines printed by the libcap wrapper:

```
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml -r ../../pcaps/smb-small-1.pcap
[15289] 14/5/2018 -- 16:10:36 - (suricata.c:1076) <Notice> (LogVersion) -- This is Suricata version 4.1.0-dev (rev 97c224d)
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'HTTP.UncompressedFlash' is checked but not set. Checked in 2016396 and 3 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.JS.Obfus.Func' is checked but not set. Checked in 2017246 and 1 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.http.PK' is checked but not set. Checked in 2019835 and 3 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.JavaArchiveOrClass' is checked but not set. Checked in 2017756 and 15 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.WinHttpRequest' is checked but not set. Checked in 2019822 and 1 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.wininet.UA' is checked but not set. Checked in 2021312 and 0 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.ip.request' is checked but not set. Checked in 2022050 and 1 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.no.exe.request' is checked but not set. Checked in 2022053 and 0 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.WinHttpRequest.no.exe.request' is checked but not set. Checked in 2022653 and 0 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.IE7.NoRef.NoCookie' is checked but not set. Checked in 2023671 and 11 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MCOFF' is checked but not set. Checked in 2019837 and 1 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'min.gethttp' is checked but not set. Checked in 2023711 and 0 other sigs
[15289] 14/5/2018 -- 16:10:37 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.armwget' is checked but not set. Checked in 2024241 and 1 other sigs
ShareCap pcap_open_offline() wrapper: given filename ../../pcaps/smb-small-1.pcap
ShareCap bypassed - using original libpcap
ShareCap pcap_datalink() wrapper
ShareCap bypassed - using original libpcap
[15289] 14/5/2018 -- 16:10:39 - (tm-threads.c:2172) <Notice> (TmThreadWaitOnThreadInit) -- all 5 packet processing threads, 4 management threads initialized, engine started.
ShareCap bypassed - using original libpcap
ShareCap pcap_close() wrapper
ShareCap bypassed - using original libpcap
[15289] 14/5/2018 -- 16:10:39 - (suricata.c:2733) <Notice> (SuricataMainLoop) -- Signal Received.  Stopping engine.
[15290] 14/5/2018 -- 16:10:39 - (source-pcap-file.c:377) <Notice> (ReceivePcapFileThreadExitStats) -- Pcap-file module read 1 files, 8 packets, 536 bytes
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata#
```

To make an actual test with ShareCap and suricata, we need to first start a ShareCap master (we will use the one explained on the previous test) and then run suricata with a "/tmp/sharecap/sharecap-" filename or "sharecap-" interface name (any of the two works the same for a simple test -- differences only with multiple partitions that are abstracted as multiple interfaces on suricata configuration) to run as a ShareCap client.
We can also run multiple suricata processes as different ShareCap clients (will all receive and process the same packets, so it's just for testing) and multiple test clients as well (the ones from previous test), for the same master. 


Instructions for suricata-sharecap integration test:

First, we start ShareCap test master reading from a pcap file and waiting for 4 clients: `./master -f ../../pcaps/smb-small-1.pcap -c 4`

Then, we start a suricata as first ShareCap client by linking with ShareCap libpcap wrapper and instructing suricata to read from a "special" pcap file with name "/tmp/sharecap/sharecap-0-0" (because it is pool 0, and client id 0): `LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml -r /tmp/sharecap/sharecap-0-0`

Next, we start two test clients with client id 1 and 2 respectively: `./client -c 1` and `./client -c 2`

Last, we start another suricata as fourth ShareCap client by linking with the libpcap wrapper and instructing suricata to read from a "special" pcap interface with name "sharecap-0-3" (pool 0, and client id 3): `LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml --pcap=sharecap-0-3`

This way we will demonstrate how both the offline/pcap file mode (-r \<pcap file\> suricata option) and live/pcap interface mode (--pcap=\<device\> suricata option) work the same way.

This is the produced output from each console:

Test master:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap# ./master -f ../../pcaps/smb-small-1.pcap -c 4
ShareCap master configured with 4 clients
Reading packets from ../../pcaps/smb-small-1.pcap file
SetShmSegmentMaxSize info: changed kernel.shmall to 524288 pages (2147483648 bytes)
SetShmSegmentMaxSize info: changed kernel.shmmax to 2147483648 bytes (524288 pages)
InitShmSegment info: created shared memory segment sharecap-shm-ring-buffer-0
InitShmRingBuffer info: shm ring buffer initialized
InitShmSegment info: created shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized master process (pid: 20520 tid: 20520) with clients 4 in the process pool 0 with 1073741824 buffer size
waiting 4 clients to start:
4 clients have been started
master reached end of pcap file ../../pcaps/smb-small-1.pcap - exiting
waiting 4 clients to exit:
4 clients have been exited
----------------
final master sharecap process results:
ShareCap master info: process pool: 0  clients: 4  shared: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmRingBuffer info: shm ring buffer cleaned up
CleanupShmSegment info: deleted shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: deleted shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed master process (pid: 20520 tid: 20520) with clients 4 from process pool 0
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap#
```

Suricata client 1 reading from dummy filename:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml -r /tmp/sharecap/sharecap-0-0
[20619] 15/5/2018 -- 12:53:10 - (suricata.c:1076) <Notice> (LogVersion) -- This is Suricata version 4.1.0-dev (rev 97c224d)
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'HTTP.UncompressedFlash' is checked but not set. Checked in 2016396 and 3 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.JS.Obfus.Func' is checked but not set. Checked in 2017246 and 1 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.http.PK' is checked but not set. Checked in 2019835 and 3 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.JavaArchiveOrClass' is checked but not set. Checked in 2017756 and 15 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.WinHttpRequest' is checked but not set. Checked in 2019822 and 1 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.wininet.UA' is checked but not set. Checked in 2021312 and 0 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.ip.request' is checked but not set. Checked in 2022050 and 1 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.no.exe.request' is checked but not set. Checked in 2022053 and 0 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.WinHttpRequest.no.exe.request' is checked but not set. Checked in 2022653 and 0 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.IE7.NoRef.NoCookie' is checked but not set. Checked in 2023671 and 11 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MCOFF' is checked but not set. Checked in 2019837 and 1 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'min.gethttp' is checked but not set. Checked in 2023711 and 0 other sigs
[20619] 15/5/2018 -- 12:53:11 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.armwget' is checked but not set. Checked in 2024241 and 1 other sigs
ShareCap pcap_open_offline() wrapper: given filename /tmp/sharecap/sharecap-0-0
Using ShareCap to get packets
Initializing ShareCap with pool_id: 0 and client_id: 0
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20619 tid: 20620) with client id 0 in the process pool 0 with 1073741824 buffer size
Initialized ShareCap with pool_id: 0 and client_id: 0
ShareCap pcap_datalink() wrapper
Using ShareCap
[20619] 15/5/2018 -- 12:53:13 - (tm-threads.c:2172) <Notice> (TmThreadWaitOnThreadInit) -- all 5 packet processing threads, 4 management threads initialized, engine started.
master is exiting - stopping pcap_dispatch() for client 0 pool 0
----------------
Closing ShareCap client 0 from pool 0
ShareCap client info: process pool: 0  client id: 0  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20619 tid: 20620) with client id 0 from process pool 0
ShareCap pcap_close() wrapper
Using ShareCap
[20619] 15/5/2018 -- 12:53:26 - (suricata.c:2733) <Notice> (SuricataMainLoop) -- Signal Received.  Stopping engine.
[20620] 15/5/2018 -- 12:53:26 - (source-pcap-file.c:377) <Notice> (ReceivePcapFileThreadExitStats) -- Pcap-file module read 1 files, 8 packets, 536 bytes
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata#
```

Client 2:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap# ./client -c 1
ShareCap client process with client id: 1
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20629 tid: 20629) with client id 1 in the process pool 0 with 1073741824 buffer size
----------------
client 1 processed: 1 pkts, 78 bytes
ShareCap client info: process pool: 0  client id: 1  processed: 1 packets 78 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 664 usage: 0.000
----------------
master is exiting - exiting client 1
----------------
final client 1 sharecap process results:
client 1 processed: 8 pkts, 536 bytes
ShareCap client info: process pool: 0  client id: 1  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20629 tid: 20629) with client id 1 from process pool 0
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap#
```

Client 3:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap# ./client -c 2
ShareCap client process with client id: 2
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20630 tid: 20630) with client id 2 in the process pool 0 with 1073741824 buffer size
master is exiting - exiting client 2
----------------
final client 2 sharecap process results:
client 2 processed: 8 pkts, 536 bytes
ShareCap client info: process pool: 0  client id: 2  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20630 tid: 20630) with client id 2 from process pool 0
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap#
```

Suricata client 4 reading from dummy interface:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml --pcap=sharecap-0-3
[20631] 15/5/2018 -- 12:53:21 - (suricata.c:1076) <Notice> (LogVersion) -- This is Suricata version 4.1.0-dev (rev 97c224d)
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'HTTP.UncompressedFlash' is checked but not set. Checked in 2016396 and 3 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.JS.Obfus.Func' is checked but not set. Checked in 2017246 and 1 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.http.PK' is checked but not set. Checked in 2019835 and 3 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.JavaArchiveOrClass' is checked but not set. Checked in 2017756 and 15 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.WinHttpRequest' is checked but not set. Checked in 2019822 and 1 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.wininet.UA' is checked but not set. Checked in 2021312 and 0 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.ip.request' is checked but not set. Checked in 2022050 and 1 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.no.exe.request' is checked but not set. Checked in 2022053 and 0 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.WinHttpRequest.no.exe.request' is checked but not set. Checked in 2022653 and 0 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.IE7.NoRef.NoCookie' is checked but not set. Checked in 2023671 and 11 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MCOFF' is checked but not set. Checked in 2019837 and 1 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'min.gethttp' is checked but not set. Checked in 2023711 and 0 other sigs
[20631] 15/5/2018 -- 12:53:21 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.armwget' is checked but not set. Checked in 2024241 and 1 other sigs
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': Operation not supported (95)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': Operation not supported (95)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': Operation not supported (95)
ShareCap pcap_create() wrapper: given device sharecap-0-3
Using ShareCap to get packets
Initializing ShareCap with pool_id: 0 and client_id: 3
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20631 tid: 20632) with client id 3 in the process pool 0 with 1073741824 buffer size
Initialized ShareCap with pool_id: 0 and client_id: 3
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:101) <Warning> (GetIfaceMTU) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get MTU via ioctl for 'sharecap': No such device (19)
ShareCap pcap_set_promisc() wrapper
Using ShareCap
ShareCap pcap_set_timeout() wrapper
Using ShareCap
ShareCap pcap_set_buffer_size() wrapper
Using ShareCap
ShareCap pcap_activate() wrapper
Using ShareCap
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20632] 15/5/2018 -- 12:53:24 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
ShareCap pcap_datalink() wrapper
Using ShareCap
[20631] 15/5/2018 -- 12:53:24 - (tm-threads.c:2172) <Notice> (TmThreadWaitOnThreadInit) -- all 5 packet processing threads, 4 management threads initialized, engine started.
master is exiting - stopping pcap_dispatch() for client 3 pool 0
----------------
Closing ShareCap client 3 from pool 0
ShareCap client info: process pool: 0  client id: 3  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20631 tid: 20632) with client id 3 from process pool 0
^C[20631] 15/5/2018 -- 12:53:41 - (suricata.c:2733) <Notice> (SuricataMainLoop) -- Signal Received.  Stopping engine.
[20631] 15/5/2018 -- 12:53:42 - (util-device.c:328) <Notice> (LiveDeviceListClean) -- Stats for 'sharecap-0-3':  pkts: 8, drop: 0 (0.00%), invalid chksum: 0
[20631] 15/5/2018 -- 12:53:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': No such device (19)
[20631] 15/5/2018 -- 12:53:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': No such device (19)
[20631] 15/5/2018 -- 12:53:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': No such device (19)
[20631] 15/5/2018 -- 12:53:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': No such device (19)
[20631] 15/5/2018 -- 12:53:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-3': No such device (19)
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# grep bytes /var/log/suricata/stats.log | tail -1
decoder.bytes                              | Total                     | 536
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata#
```


It is also possible to run suricata with two or more pcap interfaces, for example:

Test master with 2 clients:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap# ./master -f ../../pcaps/smb-small-1.pcap -c 2
ShareCap master configured with 2 clients
Reading packets from ../../pcaps/smb-small-1.pcap file
SetShmSegmentMaxSize info: changed kernel.shmall to 524288 pages (2147483648 bytes)
SetShmSegmentMaxSize info: changed kernel.shmmax to 2147483648 bytes (524288 pages)
InitShmSegment info: created shared memory segment sharecap-shm-ring-buffer-0
InitShmRingBuffer info: shm ring buffer initialized
InitShmSegment info: created shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized master process (pid: 20730 tid: 20730) with clients 2 in the process pool 0 with 1073741824 buffer size
waiting 2 clients to start:
2 clients have been started
master reached end of pcap file ../../pcaps/smb-small-1.pcap - exiting
waiting 2 clients to exit:
2 clients have been exited
----------------
final master sharecap process results:
ShareCap master info: process pool: 0  clients: 2  shared: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmRingBuffer info: shm ring buffer cleaned up
CleanupShmSegment info: deleted shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: deleted shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed master process (pid: 20730 tid: 20730) with clients 2 from process pool 0
root@papadog-vm:/media/sf_vm-data/sharecap/test_sharecap#
```

Test suricata with 2 interfaces:
```
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# LD_PRELOAD=../libpcap/libpcap.so suricata -c suricata/suricata.yaml --pcap=sharecap-0-0 --pcap=sharecap-0-1
[20782] 15/5/2018 -- 12:58:25 - (suricata.c:1170) <Warning> (ParseCommandLinePcapLive) -- [ERRCODE: SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL(177)] - using multiple pcap devices to get packets is experimental.
[20782] 15/5/2018 -- 12:58:25 - (suricata.c:1076) <Notice> (LogVersion) -- This is Suricata version 4.1.0-dev (rev 97c224d)
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'HTTP.UncompressedFlash' is checked but not set. Checked in 2016396 and 3 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.JS.Obfus.Func' is checked but not set. Checked in 2017246 and 1 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.http.PK' is checked but not set. Checked in 2019835 and 3 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.JavaArchiveOrClass' is checked but not set. Checked in 2017756 and 15 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.WinHttpRequest' is checked but not set. Checked in 2019822 and 1 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.wininet.UA' is checked but not set. Checked in 2021312 and 0 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.ip.request' is checked but not set. Checked in 2022050 and 1 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.XMLHTTP.no.exe.request' is checked but not set. Checked in 2022053 and 0 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MS.WinHttpRequest.no.exe.request' is checked but not set. Checked in 2022653 and 0 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.IE7.NoRef.NoCookie' is checked but not set. Checked in 2023671 and 11 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'et.MCOFF' is checked but not set. Checked in 2019837 and 1 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'min.gethttp' is checked but not set. Checked in 2023711 and 0 other sigs
[20782] 15/5/2018 -- 12:58:26 - (detect-flowbits.c:475) <Warning> (DetectFlowbitsAnalyze) -- [ERRCODE: SC_WARN_FLOWBIT(306)] - flowbit 'ET.armwget' is checked but not set. Checked in 2024241 and 1 other sigs
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': Operation not supported (95)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': Operation not supported (95)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': Operation not supported (95)
ShareCap pcap_create() wrapper: given device sharecap-0-0
Using ShareCap to get packets
Initializing ShareCap with pool_id: 0 and client_id: 0
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20782 tid: 20783) with client id 0 in the process pool 0 with 1073741824 buffer size
Initialized ShareCap with pool_id: 0 and client_id: 0
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:101) <Warning> (GetIfaceMTU) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get MTU via ioctl for 'sharecap': No such device (19)
ShareCap pcap_set_promisc() wrapper
Using ShareCap
ShareCap pcap_set_timeout() wrapper
Using ShareCap
ShareCap pcap_set_buffer_size() wrapper
Using ShareCap
ShareCap pcap_activate() wrapper
Using ShareCap
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20783] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
ShareCap pcap_datalink() wrapper
Using ShareCap
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': Operation not supported (95)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': Operation not supported (95)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': Operation not supported (95)
ShareCap pcap_create() wrapper: given device sharecap-0-1
Using ShareCap to get packets
Initializing ShareCap with pool_id: 0 and client_id: 1
InitShmSegment info: attached shared memory segment sharecap-shm-ring-buffer-0
InitShmSegment info: attached shared memory segment sharecap-shm-mem-pool-0
ShareCapInitProcessCommon info: initialized client process (pid: 20782 tid: 20816) with client id 1 in the process pool 0 with 1073741824 buffer size
Initialized ShareCap with pool_id: 0 and client_id: 1
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:101) <Warning> (GetIfaceMTU) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get MTU via ioctl for 'sharecap': No such device (19)
ShareCap pcap_set_promisc() wrapper
Using ShareCap
ShareCap pcap_set_timeout() wrapper
Using ShareCap
ShareCap pcap_set_buffer_size() wrapper
Using ShareCap
ShareCap pcap_activate() wrapper
Using ShareCap
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
[20816] 15/5/2018 -- 12:58:28 - (util-ioctl.c:289) <Warning> (GetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap': No such device (19)
ShareCap pcap_datalink() wrapper
Using ShareCap
[20782] 15/5/2018 -- 12:58:28 - (tm-threads.c:2172) <Notice> (TmThreadWaitOnThreadInit) -- all 6 packet processing threads, 4 management threads initialized, engine started.
master is exiting - stopping pcap_dispatch() for client 1 pool 0
----------------
Closing ShareCap client 1 from pool 0
ShareCap client info: process pool: 0  client id: 1  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
master is exiting - stopping pcap_dispatch() for client 0 pool 0
----------------
Closing ShareCap client 0 from pool 0
ShareCap client info: process pool: 0  client id: 0  processed: 8 packets 536 bytes
ShareCap shm ring buffer info: size: 1073741824 used: 0 usage: 0.000
----------------
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20782 tid: 20816) with client id 1 from process pool 0
CleanupShmSegment info: detached shared memory segment sharecap-shm-ring-buffer-0
CleanupShmSegment info: detached shared memory segment sharecap-shm-mem-pool-0
ShareCapRemoveProcess info: removed client process (pid: 20782 tid: 20783) with client id 0 from process pool 0
^C[20782] 15/5/2018 -- 12:58:41 - (suricata.c:2733) <Notice> (SuricataMainLoop) -- Signal Received.  Stopping engine.
[20782] 15/5/2018 -- 12:58:42 - (util-device.c:328) <Notice> (LiveDeviceListClean) -- Stats for 'sharecap-0-0':  pkts: 8, drop: 0 (0.00%), invalid chksum: 0
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-0': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-device.c:328) <Notice> (LiveDeviceListClean) -- Stats for 'sharecap-0-1':  pkts: 8, drop: 0 (0.00%), invalid chksum: 0
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': No such device (19)
[20782] 15/5/2018 -- 12:58:42 - (util-ioctl.c:317) <Warning> (SetEthtoolValue) -- [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to get feature via ioctl for 'sharecap-0-1': No such device (19)
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata# grep bytes /var/log/suricata/stats.log | tail -1
decoder.bytes                              | Total                     | 1072
root@papadog-vm:/media/sf_vm-data/sharecap/test_suricata#
```

In this example, both dummy interfaces get the same packets, which is not the use case we are interested in. However, with different pools they can get packets from different interfaces or different partitions from a 10+ Gb interface to process in parallel.

We also verified that suricata output results (stats and detection results) match when using native libpcap mode (or AF\_PACKET mode) and ShareCap libpcap wrapper when replaying the same traffic. Both suricata stats and alerts logged are quite close or identical in both cases, so we believe we get the same output results using ShareCap.


### Performance Benchmark

We measure the performance of ShareCap and suricata using ShareCap to receive packets, and compare with the libpcap or AF\_PACKET alternatives.
We compare native ShareCap programs, native libpcap, and ShareCap libpcap wrapper using both virtual files or virtual interfaces.
The benchmark script and some results of this benchmark can be found in the https://github.com/apapadog/sharecap/blob/main/benchmark directory.
This is the benchmark script: https://github.com/apapadog/sharecap/blob/main/benchmark/sharecap-benchmark.sh

Instructions for running the script: simply run `./sharecap-benchmark.sh`

Some results can be found below, also in https://github.com/apapadog/sharecap/blob/main/benchmark/results-1.txt 

Also, individual checks for suricata output (stats and alerts logged) show very close or identical results in all cases (small differences due to additional background packets coming or suricata initialization time). The full suticata output checks are yet to be added on the benchmark script in future version (and some differences to be explored).


#### Packet capture benchmark

We measure the performance of the ShareCap test master and client processes when capturing packets live from an interface, and compare with the performance of a native libpcap packet capture test program. We also compare the performance of the same capture capture test program through the ShareCap libpcap wrapper as well, both using virtual file and interface.


#### Suricata benchmark

We compare the performance of suricata using native libpcap, AF\_PACKET, and ShareCap (through its libpcap wrapper) using a default config and ruleset.
For suricata using ShareCap libpcap wrapper, we try both using the virtual ShareCap file and virtual ShareCap interface.


#### Results

```
capture_test	pcap_small_rewr.pcap	CPU: 19%	System mem used: 4994.95 MB	Mem: 23.4805 MB	MRSS: 16.7109 MB	Bytes: 1176564571	Packets: 1720794	Average packet size: 683.73353870364494529850 bytes	Processing throughput: 3765.00662720000000000000 Mbps							
sharecap_native_test	pcap_small_rewr.pcap	CPU: 11%	System mem used: 4994.95 MB	Mem: 1033.39 MB	MRSS: 1024.72 MB	Bytes: 1168366476	Packets: 1708429	Average packet size: 683.88354213139673934357 bytes	Processing throughput: 5664.80715636363636363636 Mbps	Master CPU: 21%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 2409.00304329896907216494 Mbps			
sharecap_wrapper_file_test	pcap_small_rewr.pcap	CPU: 12%	System mem used: 6024.02 MB	Mem: 1039.68 MB	MRSS: 1024.8 MB	Bytes: 1171094704	Packets: 1712784	Average packet size: 683.73753141084923726517 bytes	Processing throughput: 5478.80563274853801169590 Mbps	Master CPU: 22%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 2336.34853665835411471321 Mbps			
sharecap_wrapper_interface_test	pcap_small_rewr.pcap	CPU: 35%	System mem used: 6023.25 MB	Mem: 1039.68 MB	MRSS: 1024.79 MB	Bytes: 1177683438	Packets: 1722369	Average packet size: 683.75791598664397698750 bytes	Processing throughput: 1524.50930485436893203883 Mbps	Master CPU: 22%	Master mem usage: 1051.64 MB	Master MRSS: 1040.84 MB	Master processing throughput: 2343.64863283582089552238 Mbps			
suricata_pcap_test	pcap_small_rewr.pcap	CPU: 97%	System mem used: 5266.57 MB	Mem: 1209.37 MB	MRSS: 279.805 MB	Bytes: 1164877902	Packets: 1704196	Average packet size: 683.53516966358329675694 bytes	Processing throughput: 441.86928477951635846372 Mbps					Flows: 7129	Average flow size: 163399.90209005470612989199 bytes	Flows/sec: 329.74098057354301572617
suricata_afpacket_test	pcap_small_rewr.pcap	CPU: 92%	System mem used: 5285.66 MB	Mem: 1138.62 MB	MRSS: 294.703 MB	Bytes: 1163792364	Packets: 1707419	Average packet size: 681.60912113546821254771 bytes	Processing throughput: 477.45327753846153846153 Mbps					Flows: 7143	Average flow size: 162927.67240655186896262074 bytes	Flows/sec: 336.93396226415094339622
suricata_sharecap_file_test	pcap_small_rewr.pcap	CPU: 92%	System mem used: 6310.68 MB	Mem: 2163.42 MB	MRSS: 1298.43 MB	Bytes: 1180364277	Packets: 1726497	Average packet size: 683.67583436287465312711 bytes	Processing throughput: 471.67403676323676323676 Mbps	Master CPU: 13%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 2697.97549028571428571428 Mbps	Flows: 7125	Average flow size: 165665.16168421052631578947 bytes	Flows/sec: 327.58620689655172413793
suricata_sharecap_interface_test	pcap_small_rewr.pcap	CPU: 93%	System mem used: 6311.34 MB	Mem: 2235.42 MB	MRSS: 1304.58 MB	Bytes: 1179629066	Packets: 1726735	Average packet size: 683.15582066732880262460 bytes	Processing throughput: 388.67514530477759472817 Mbps	Master CPU: 13%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 2735.37174724637681159420 Mbps	Flows: 7125	Average flow size: 165561.97417543859649122807 bytes	Flows/sec: 274.46070878274268104776
capture_test	office_dump_rewr.pcap	CPU: 50%	System mem used: 4996.65 MB	Mem: 23.4805 MB	MRSS: 16.7109 MB	Bytes: 2097721493	Packets: 5726301	Average packet size: 366.33098626844799112027 bytes	Processing throughput: 2390.56580398860398860398 Mbps							
sharecap_native_test	office_dump_rewr.pcap	CPU: 28%	System mem used: 4996.65 MB	Mem: 1033.39 MB	MRSS: 1016.65 MB	Bytes: 2112690177	Packets: 5780512	Average packet size: 365.48495652288240211247 bytes	Processing throughput: 3995.63154042553191489361 Mbps	Master CPU: 48%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 1815.41583415682062298603 Mbps			
sharecap_wrapper_file_test	office_dump_rewr.pcap	CPU: 32%	System mem used: 6025.04 MB	Mem: 1039.68 MB	MRSS: 1016.54 MB	Bytes: 2123491234	Packets: 5823142	Average packet size: 364.66416824456624962949 bytes	Processing throughput: 3459.86351771894093686354 Mbps	Master CPU: 50%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 1765.89707609147609147609 Mbps			
sharecap_wrapper_interface_test	office_dump_rewr.pcap	CPU: 52%	System mem used: 6024.61 MB	Mem: 1039.68 MB	MRSS: 1016.12 MB	Bytes: 2106063682	Packets: 5756404	Average packet size: 365.86446712218252923179 bytes	Processing throughput: 1678.13839203187250996015 Mbps	Master CPU: 49%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 1764.24182785340314136125 Mbps			
suricata_pcap_test	office_dump_rewr.pcap	CPU: 237%	System mem used: 5557.43 MB	Mem: 1209.37 MB	MRSS: 564.172 MB	Bytes: 2059548387	Packets: 5683934	Average packet size: 362.34558441389361663946 bytes	Processing throughput: 300.06168450191221999635 Mbps					Flows: 25789	Average flow size: 79861.50633991236573732986 bytes	Flows/sec: 1113.99568034557235421166
suricata_afpacket_test	office_dump_rewr.pcap	CPU: 176%	System mem used: 5571.84 MB	Mem: 1138.62 MB	MRSS: 571.637 MB	Bytes: 1431253379	Packets: 5667707	Average packet size: 252.52776457922048546263 bytes	Processing throughput: 282.36811422934648581997 Mbps					Flows: 25344	Average flow size: 56473.06577493686868686868 bytes	Flows/sec: 1102.39234449760765550239
suricata_sharecap_file_test	office_dump_rewr.pcap	CPU: 195%	System mem used: 6669.56 MB	Mem: 2163.42 MB	MRSS: 1591.89 MB	Bytes: 2105316934	Packets: 5764307	Average packet size: 365.23331148046070412280 bytes	Processing throughput: 352.13329441772945849885 Mbps	Master CPU: 27%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 2170.42982886597938144329 Mbps	Flows: 25184	Average flow size: 83597.40049237611181702668 bytes	Flows/sec: 1030.86369218174375767498
suricata_sharecap_interface_test	office_dump_rewr.pcap	CPU: 193%	System mem used: 6606.37 MB	Mem: 2235.42 MB	MRSS: 1590.96 MB	Bytes: 2121624735	Packets: 5813815	Average packet size: 364.92814700846174155868 bytes	Processing throughput: 315.13178388414407723728 Mbps	Master CPU: 27%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 2281.31691935483870967741 Mbps	Flows: 25286	Average flow size: 83905.11488570750612987423 bytes	Flows/sec: 907.60947595118449389806
capture_test	pcap_2gb_rewr.pcap	CPU: 15%	System mem used: 4998.09 MB	Mem: 23.4805 MB	MRSS: 16.7109 MB	Bytes: 3199421780	Packets: 9721015	Average packet size: 329.12425091412779426839 bytes	Processing throughput: 2263.07464544650751547303 Mbps							
sharecap_native_test	pcap_2gb_rewr.pcap	CPU: 8%	System mem used: 4998.09 MB	Mem: 1033.39 MB	MRSS: 1024.72 MB	Bytes: 3227323152	Packets: 9819512	Average packet size: 328.66431162770614262704 bytes	Processing throughput: 3830.65062551928783382789 Mbps	Master CPU: 22%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 1448.85438922558922558922 Mbps			
sharecap_wrapper_file_test	pcap_2gb_rewr.pcap	CPU: 10%	System mem used: 6024.89 MB	Mem: 1039.68 MB	MRSS: 1024.79 MB	Bytes: 3253337170	Packets: 9910609	Average packet size: 328.26813871882141652445 bytes	Processing throughput: 3460.99698936170212765957 Mbps	Master CPU: 23%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 1408.37106926406926406926 Mbps			
sharecap_wrapper_interface_test	pcap_2gb_rewr.pcap	CPU: 16%	System mem used: 6025.59 MB	Mem: 1039.68 MB	MRSS: 1024.79 MB	Bytes: 3214649816	Packets: 9774595	Average packet size: 328.87805745404285292638 bytes	Processing throughput: 2034.58849113924050632911 Mbps	Master CPU: 23%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 1378.93825887399463806970 Mbps			
suricata_pcap_test	pcap_2gb_rewr.pcap	CPU: 101%	System mem used: 5410.87 MB	Mem: 1273.37 MB	MRSS: 412.605 MB	Bytes: 3249078507	Packets: 9931316	Average packet size: 327.15488128662908319501 bytes	Processing throughput: 294.80127090847226947941 Mbps					Flows: 25437	Average flow size: 127730.41266658804104257577 bytes	Flows/sec: 292.14425175146433903755
suricata_afpacket_test	pcap_2gb_rewr.pcap	CPU: 75%	System mem used: 5429.35 MB	Mem: 1202.62 MB	MRSS: 429.461 MB	Bytes: 2767557028	Packets: 9835895	Average packet size: 281.37317732651680401224 bytes	Processing throughput: 335.05533026634382566585 Mbps					Flows: 24978	Average flow size: 110799.78493073905036432060 bytes	Flows/sec: 285.88760444088359848918
suricata_sharecap_file_test	pcap_2gb_rewr.pcap	CPU: 83%	System mem used: 6453.72 MB	Mem: 2227.42 MB	MRSS: 1431.79 MB	Bytes: 3189809280	Packets: 9726334	Average packet size: 327.95596778806896822584 bytes	Processing throughput: 344.61140094530722484807 Mbps	Master CPU: 16%	Master mem usage: 1051.64 MB	Master MRSS: 1040.82 MB	Master processing throughput: 1811.10533995741660752306 Mbps	Flows: 24588	Average flow size: 129730.32698877501220107369 bytes	Flows/sec: 278.58599592114208021753
suricata_sharecap_interface_test	pcap_2gb_rewr.pcap	CPU: 88%	System mem used: 6453.61 MB	Mem: 2299.42 MB	MRSS: 1431.11 MB	Bytes: 3262931314	Packets: 9924042	Average packet size: 328.79055872597072845923 bytes	Processing throughput: 320.05211515448749386954 Mbps	Master CPU: 16%	Master mem usage: 1051.64 MB	Master MRSS: 1040.83 MB	Master processing throughput: 1846.07146478076379066478 Mbps	Flows: 25174	Average flow size: 129615.13124652419162628108 bytes	Flows/sec: 274.10714285714285714285
```


### TODO

- Unit tests
- Add stats for dropped-packets and dropped-bytes and update from master (available to read from clients). Drop based on slower client (drop same packets for all clients), or implement a different policy with some faster consumer not dropping (dropping less) than other consumers.
- Wrap the rest libpcap functions in libpcap wrapper for ShareCap clients (functions not being used by suricata currently)
- Another test with threads instead of processes
- Another test with multiple interfaces or multiple fanout partitions, using multiple shared memory segments / sharecap instances
- More tests: test with other libpcap tools, DPI using threads and processes, other processing tools
- Add checks for suricata output and detection results (stats, alerts) in the benchmark
- Add PF\_RING and/or other alternatives in the benchmark
- Add to benchmark: compare with 2 or N processes capture through libpcap/afpacket at the same time (same packets) without shared memory - same using pfring (which should have packet memory sharing) - to evaluate what we gain with packet sharing. Compare with bridge/reflect packets from one interface to another like pfreflect or pfbridge (from pfring)


### Contact

apapadog@gmail.com

