/*
 * ISA Project
 * 
 * File: flows.h
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pcap.h>

#include "utilities.h"

#define SIZE_ETHERNET (14)
#define NETFLOW_VERSION (5)
#define FLOW_TOTAL_SIZE (72) //size of one netflow packet
#define FLOW_HEADER_SIZE (24) //size of netflow header
#define FLOW_RECORD_SIZE (48) //size of netflow body

struct Node {
	struct Key* key;
	struct Flow* flow;
	
	struct Node* next;
	struct Node* prev;
};

struct Key {
	uint32_t source_ip;
	uint32_t dest_ip;
	uint16_t source_port;
	uint16_t dest_port;
	u_int8_t protocol;
};

struct FlowHeader {
	uint16_t version;
	uint16_t count;
	uint32_t SysUptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint32_t flow_sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint16_t sampling_interval;
};

struct FlowRecord {
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t dPkts;
	uint32_t dOctets;
	uint32_t First;
	uint32_t Last;
	uint16_t srcport;
	uint16_t dstport;
	uint8_t pad1;
	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint16_t pad2;
};

struct Flow {
	struct FlowHeader* header;
	struct FlowRecord* record;
};

/*
 * Prints content of the flows list
 * Used only for debugging
 */
void displayForward();

/*
 * Returns true if both keys contain the same 5 values:
 * 	- source address
 * 	- destination address
 * 	- source port
 *  - destination port
 *  - protocol
 */
bool compare_keys(struct Key* key1, struct Key* key2);

/*
 * Returns true if the flow cache is empty
 */
bool is_empty();

/*
 * Checks if the flow cache is full
 * If so, pops the oldest flow and exports it
 */
void check_cache_capacity();

/*
 * Returns true if flow with given key is already present in the flow cache
 */
bool key_exists(struct Key* key);

/*
 * Inserts new flow with given key to the end of the flow cache
 */
void insert_last(struct Key* key, struct Flow* flow);

/*
 * Returns (and removes) the oldest flow from the flow cache
 */
struct Flow* pop_first();

/*
 * Returns (and removes) the flow contained in node pointed to by ptr
 */
struct Flow* pop_node(struct Node* ptr);

/*
 * Returns (and removes) the flow with given key
 */
struct Flow* pop_with_given_key(struct Key* key);

/*
 * Updates the flow with given key
 * Params:
 *  - newLast - Timestamp of the latest processed packet
 *  - new_packet_size - size of the processed packet
 *  - new_tcp_flags - tcp flags of the processed packet (bitwise OR with the current flags)
 */
void update_flow(struct Key* key, uint32_t new_Last, uint32_t new_packet_size, uint8_t new_tcp_flags);

/*
 * Iterates through all flows and checks if any of them expired
 * If so, exports them and removes them from the cache
 */
void check_active_timer();
void check_inactive_timer(uint32_t current_sys_uptime);

/*
 * Converts the data in flow to network byteorder
 * Creates the final flow packet and sends it to collector
 * (collector address specified by user or implicit localhost:2055)
 */
void export_flow(struct Flow* flow);

/*
 * Called at the end of the program
 * Iterates through the remaining flows in the flow cache and exports them
 */
void export_remaining_flows();

/*
 * Takes a packet and breaks it down layer after layer,
 * decides whether it's a TCP, UDP or ICMP packet.
 * Then constructs the packet's key and either creates a new flow
 * or updates an existing flow with the packets data.
 * Params:
 *  - header - pointer to the header of the Ethernet packet
 *  - packet - pointer to the body (data) of the Ethernet packet
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
