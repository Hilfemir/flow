/*
 * ISA Project
 * 
 * File: flows.c
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "flows.h"

extern int cache_size;
extern uint32_t active_timer;
extern uint32_t inactive_timer;
extern int sock;

struct Node *head = NULL; //first item of the flow list
struct Node *last = NULL; //last item of the flow list

int count = 0; //number of flows stored in cache
uint32_t oldest = 0; //timestamp of the first recorded packet
int sequence_counter = 0; //total number of flows seen in this sequence
uint32_t current_unix_secs = 0;
uint32_t current_unix_nsecs = 0;

/*******************************************/

int i = 1;

void process_packet(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    struct ether_header *eptr; //pointer to the Ether header
    struct ip* my_ip; //pointer to the IP header
    const struct tcphdr *my_tcp; //pointer to the TCP header
    const struct udphdr *my_udp; //pointer to the UDP header
    const struct icmphdr *my_icmp; //pointer to the ICMP header
    u_int size_ip;
    uint8_t tcp_flags = 0;
    
	struct Key* key = (struct Key*) malloc(sizeof(struct Key));
    
    //calculate current timestamp
    uint32_t packet_timestamp = calculate_timestamp(packet_header->ts);
    uint32_t unix_secs = packet_header->ts.tv_sec;
    uint32_t unix_nsecs = packet_header->ts.tv_usec * 1000;
    
    //update the global vars
    current_unix_secs = unix_secs;
    current_unix_nsecs = unix_nsecs;
    
    //if it's the first packet, use its timestamp as the reference "boot" time
    if (oldest == 0)
		oldest = packet_timestamp;
    
    uint32_t sys_uptime = packet_timestamp - oldest;
    
    //check if any of the existing flows expired and eventually export them
    check_active_timer();
    check_inactive_timer(sys_uptime);
    
    eptr = (struct ether_header*) packet_body;
    
    //check if it's an IPv4 packet
	if (ntohs(eptr->ether_type) != ETHERTYPE_IP)
		return;
		
	my_ip = (struct ip*) (packet_body+SIZE_ETHERNET);
	size_ip = my_ip->ip_hl*4;
	
	key->source_ip = my_ip->ip_src.s_addr;
	key->dest_ip   = my_ip->ip_dst.s_addr;
	key->protocol  = my_ip->ip_p;
	
	switch (my_ip->ip_p) {
		case 1: //ICMP
			my_icmp = (struct icmphdr*) (packet_body+SIZE_ETHERNET+size_ip);
			
			key->source_port = 0;
			key->dest_port = my_icmp->type * 256 + my_icmp->code;
			tcp_flags = 0;
			break;
			
		case 6: //TCP
			my_tcp = (struct tcphdr*) (packet_body+SIZE_ETHERNET+size_ip); //get to the start of the TCP header
			
			key->source_port = ntohs(my_tcp->th_sport);
			key->dest_port = ntohs(my_tcp->th_dport);
			
			tcp_flags = my_tcp->th_flags;
			
			break;
			
		case 17: //UDP
			my_udp = (struct udphdr*) (packet_body+SIZE_ETHERNET+size_ip); //get to the start of the UDP header
			
			key->source_port = ntohs(my_udp->uh_sport);
			key->dest_port = ntohs(my_udp->uh_dport);
			tcp_flags = 0;
			break;
	}
	
	if (key_exists(key)) { //update an existing flow
		update_flow(key, sys_uptime, (u_int32_t) ntohs(my_ip->ip_len), tcp_flags);
	}
	else { //create a new flow
		struct FlowHeader* flow_header = (struct FlowHeader*) malloc(sizeof(struct FlowHeader));
		struct FlowRecord* flow_record = (struct FlowRecord*) malloc(sizeof(struct FlowRecord));
		struct Flow* flow = (struct Flow*) malloc(sizeof(struct Flow));
	
		//header values
		flow_header->version           = NETFLOW_VERSION;
		flow_header->count             = 1;
		flow_header->SysUptime         = sys_uptime;
		flow_header->unix_secs         = unix_secs;
		flow_header->unix_nsecs        = unix_nsecs;
		flow_header->flow_sequence     = sequence_counter;
		flow_header->engine_type       = 0;
		flow_header->engine_id         = 0;
		flow_header->sampling_interval = 0;
		
		//record values
		flow_record->srcaddr   = key->source_ip;
		flow_record->dstaddr   = key->dest_ip;
		flow_record->nexthop   = 0;
		flow_record->input     = 0;
		flow_record->output    = 0;
		flow_record->dPkts     = 1;
		flow_record->dOctets   = (u_int32_t) ntohs(my_ip->ip_len);
		flow_record->First     = sys_uptime;
		flow_record->Last      = sys_uptime;
		flow_record->srcport   = key->source_port;
		flow_record->dstport   = key->dest_port;
		flow_record->pad1      = 0;
		flow_record->tcp_flags = tcp_flags;
		flow_record->prot      = key->protocol;
		flow_record->tos       = my_ip->ip_tos;
		flow_record->src_as    = 0;
		flow_record->dst_as    = 0;
		flow_record->src_mask  = 0;
		flow_record->dst_mask  = 0;
		flow_record->pad2      = 0;	
		
		flow->header = flow_header;
		flow->record = flow_record;
		
		insert_last(key, flow);
	}
	
	//export flow if TCP connection has ended
	if ((tcp_flags & TH_FIN) || (tcp_flags & TH_RST)) {
		struct Flow* flow_to_export = pop_with_given_key(key);
		export_flow(flow_to_export);
		return;
	}
	
	displayForward();
    return;
}

/*******************************************/

bool is_empty() {
	return head == NULL;
}

/*******************************************/

void check_cache_capacity() {
	if (count >= cache_size) {
		struct Flow* flow_to_export = pop_first();
		export_flow(flow_to_export);
	}
}

/*******************************************/

bool compare_keys(struct Key* key1, struct Key* key2) {
	if (key1->source_ip   == key2->source_ip &&
		key1->dest_ip     == key2->dest_ip   &&
		key1->source_port == key2->source_port &&
		key1->dest_port   == key2->dest_port   &&
		key1->protocol    == key2->protocol) {
			return true;
	}
	
	return false;
}

/*******************************************/

bool key_exists(struct Key* key) {
	struct Node* ptr = head;
	
	while (ptr != NULL) {
		if (compare_keys(key, ptr->key)) {
			return true;
		}
		ptr = ptr->next;
	}
	
	return false;
}

/*******************************************/

void insert_last(struct Key* key, struct Flow* flow) {
	check_cache_capacity();
	
	struct Node* link = (struct Node*) malloc(sizeof(struct Node));
	link->key = key;
	link->flow = flow;
	
	if (!is_empty()) {
		last->next = link;
		link->prev = last;
	}
	
	last = link;
	
	if (is_empty()) {
		head = link;
	}
	
	last->next = NULL;
	
	count++;
}

/*******************************************/

struct Flow* pop_first() {
	if(is_empty())
		return NULL;
		
	struct Flow* ret = head->flow;
	
	struct Node* tmp = head->next;
	if (tmp == NULL)
		head = NULL;
	else
		head = tmp;
		
	count--;
	
	return ret;
}

/*******************************************/

void update_flow(struct Key* key, uint32_t new_Last, uint32_t new_packet_size, uint8_t new_tcp_flags) {
	struct Node* ptr = head;
	
	while (ptr != NULL) {
		if (compare_keys(key, ptr->key)) {
			ptr->flow->record->Last = new_Last;
			ptr->flow->record->dOctets += new_packet_size;
			ptr->flow->record->tcp_flags |= new_tcp_flags;
			ptr->flow->record->dPkts++;
			
			return;
		}
		
		ptr = ptr->next;
	}
}

/*******************************************/

void check_active_timer() {
	struct Node* ptr = head;
	
	while (ptr != NULL) {
		//active timer: Last - First > a
		if ((ptr->flow->record->Last - ptr->flow->record->First) > active_timer) {
			printf("some flow expired - active");
			struct Flow* exported_flow = pop_node(ptr);
			export_flow(exported_flow);
		}
		ptr = ptr->next;
	}
}

/*******************************************/

void check_inactive_timer(uint32_t current_sys_uptime) {
	struct Node* ptr = head;
	
	while(ptr != NULL) {
		//inactive timer: current_packet - Last > i
		if ((current_sys_uptime - ptr->flow->record->Last) > inactive_timer) {
			printf("some flow expired - inactive\n");
			struct Flow* exported_flow = pop_node(ptr);
			export_flow(exported_flow);
		}
		ptr = ptr->next;
	}
}

/*******************************************/

struct Flow* pop_node(struct Node* ptr) {
	struct Flow* ret = ptr->flow;
	
	if (ptr->next == NULL && ptr->prev == NULL) { //the only node
		head = NULL;
		last = NULL;
	}
	else if (ptr == last) { //last node
		last = ptr->prev;
		last->next = NULL;
	}
	else if (ptr == head) { //first node
		head = ptr->next;
		head->prev = NULL;
	}
	else { //the node is somewhere in the middle
		ptr->prev->next = ptr->next;
		ptr->next->prev = ptr->prev;
	}
	
	count--;
	return ret;
}

/*******************************************/

struct Flow* pop_with_given_key(struct Key* key) {
	struct Node* ptr = head;
	struct Flow* ret;
	
	while (ptr != NULL) {
		if (compare_keys(key, ptr->key)) {
			ret = ptr->flow;
			
			if (ptr->next == NULL && ptr->prev == NULL) {
				head = NULL;
				last = NULL;
			}
			else if (ptr == last) { //last node
				last = ptr->prev;
				last->next = NULL;
			}
			else if (ptr == head) { //first node
				head = ptr->next;
				head->prev = NULL;
			}
			else { //the node is somewhere inside the list
				ptr->prev->next = ptr->next;
				ptr->next->prev = ptr->prev;
			}
			
			count--;
			return ret;
		}
		
		ptr = ptr->next;
	}
}

/*******************************************/

void export_flow(struct Flow* flow) {
	//convert all items (larger than 1 byte) in flow to network byteorder
	flow->header->version       = htons(flow->header->version);
	flow->header->count         = htons(flow->header->count);
	flow->header->SysUptime     = htonl(flow->header->SysUptime);
	flow->header->unix_secs     = htonl(current_unix_secs);
	flow->header->unix_nsecs    = htonl(current_unix_nsecs);
	flow->header->flow_sequence = htonl(++sequence_counter);
	
	flow->record->dPkts   = htonl(flow->record->dPkts);
	flow->record->dOctets = htonl(flow->record->dOctets);
	flow->record->First   = htonl(flow->record->First);
	flow->record->Last    = htonl(flow->record->Last);
	flow->record->srcport = htons(flow->record->srcport);
	flow->record->dstport = htons(flow->record->dstport);
	//source and dest addresses are already in a correct byteorder
	
	uint8_t* buffer = malloc(FLOW_TOTAL_SIZE);
	
	memcpy(buffer, flow->header, FLOW_HEADER_SIZE);
	memcpy(buffer+FLOW_HEADER_SIZE, flow->record, FLOW_RECORD_SIZE);
	
	int i = send(sock, buffer, FLOW_TOTAL_SIZE, 0);
	
	if (i == -1)
		error("Error: send() failed\n", 1);
	else if (i != FLOW_TOTAL_SIZE)
		error("Error: send() buffer written partially\n", 1);
	
	free(buffer);
	free(flow->header);
	free(flow->record);
	free(flow);
	
	printf("sent out packet woohoo\n");
}

/*******************************************/

void export_remaining_flows() {
	struct Node* ptr = head;
	struct Flow* ret;
	
	while (ptr != NULL) {
		ret = pop_first();
		export_flow(ret);
		
		ptr = head;
	}
}

/*******************************************/

void displayForward() {

   //start from the beginning
   struct Node *ptr = head;
	
	printf("Number of nodes: %d\n", count);
	
   //navigate till the end of the list
   printf("[ ");

   while(ptr != NULL) {     
      printf("(%u, dOctets = %u) ",ptr->key->source_port, ptr->flow->record->dOctets);
      ptr = ptr->next;
   }
	
   printf(" ]\n\n");
}
