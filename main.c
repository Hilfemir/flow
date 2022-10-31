/*
 * ISA Project
 * 
 * File: main.c
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>

#include "argparse.h"
#include "utilities.h"
#include "flows.h"

/* GLOBAL VARIABLES */

int cache_size = 1024; //max number of cached flows
int sock; //socket descriptor
uint32_t active_timer;
uint32_t inactive_timer;

int main(int argc, char **argv)
{
	/*
	 * Potential arguments (all optional):
	 * -f <file>                       - name of the input file (STDIN implicit)
	 * -c <netflow_collector>[:<port>] - IP address or hostname of the NetFlow collector (127.0.0.1:2055 implicit)
	 * -a <active_timer>               - interval [seconds] after which the active entries are exported to the collector (60 implicit)
	 * -i <inactive_timer>             - interval after which the inactive entries are exported (10 implicit)
	 * -m <count>                      - size of the flow-cache (1024 implicit)
	 */
	struct Arguments arguments;
	arguments.input_file = "stdin";
	arguments.netflow_collector_addr = "127.0.0.1";
	arguments.netflow_collector_port = "2055";
	arguments.active_timer = 60;
	arguments.inactive_timer = 10;
	arguments.cache_size = 1024;
	
	pcap_t *handle; //handle to the pcap file used in the pcap_loop() function
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char* filter_str = "proto 1 or 6 or 17"; //accept only UDP, TCP and ICMP packets
	struct sockaddr_in collector; //address structure of the collector
	struct hostent *collent; //network host entry required by gethostbyname()
	FILE* f = NULL; //pointer to the pcap file
	
	/* PARSING ARGUMENTS */
	if (argc > 1) {
		parse_arguments(argc, argv, &arguments);
	}
	
	cache_size = arguments.cache_size;
	active_timer = (uint32_t) arguments.active_timer * 1000; //convert to miliseconds
	inactive_timer = (uint32_t) arguments.inactive_timer * 1000;
	
	/* SETTING UP COLLECTOR ADDRESS AND PORT */
	memset(&collector, 0, sizeof(collector)); //erase the collector structure
	collector.sin_family = AF_INET;
	
	//DNS resolution of the supposed collector address
	if((collent = gethostbyname(arguments.netflow_collector_addr)) == NULL)
		error("Error: gethostbyname() failed\n", 7);
		
	memcpy(&collector.sin_addr, collent->h_addr, collent->h_length); //collector address
	
	collector.sin_port = htons(atoi(arguments.netflow_collector_port)); //collector port
	
	/* READING PACKETS FROM STDIN */
	if (strcmp(arguments.input_file, "stdin") == 0) {
		handle = pcap_open_offline("-", error_buffer);
		
		if (handle == NULL)
			error("Could not open file\n", 3);
	}
	
	/* OR READING PACKETS FROM A FILE */
	else {
		f = fopen(arguments.input_file, "r");
		if (f == NULL)
			error("Could not open file\n", 3);
			
		handle = pcap_fopen_offline(f, error_buffer);
		
		if (handle == NULL)
			error("Could not open file\n", 3);
	}
	
	/* SETTING UP THE FILTER */
	// compile the string and pass it to the filter
	if (pcap_compile(handle, &filter, filter_str, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
		char* error_message = pcap_geterr(handle);
		error(error_message, 1);
	}
	
	if (pcap_setfilter(handle, &filter) != 0) {
		error("pcap_setfilter() error\n", 1);
	}
	
	/* CREATING SOCKET */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		error("Error: failed creating a socket\n", 9);
	
	/* CREATING UDP CONNECTION */
	if (connect(sock, (struct sockaddr*)&collector, sizeof(collector)) == -1)
		error("Error: connect() failed\n", 1);
	
	/* LOOPING THROUGH THE PACKETS AND CREATING NETFLOW RECORDS */
	pcap_loop(handle, 0, process_packet, NULL);
	
	export_remaining_flows();
	
	if (f != NULL)
		fclose(f);
	close(sock);
	
	return 0;
}
