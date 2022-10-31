/*
 * ISA Project
 * 
 * File: argparse.c
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <string.h>
#include <ctype.h>

#include "utilities.h"
#include "argparse.h"

void parse_arguments(int argc, char** argv, struct Arguments* arguments) {
	int opt;
	
	while ((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
		switch(opt) {
			case 'f':
				arguments->input_file = optarg;
				break;
			case 'c': ;
				char* token = strtok(optarg, ":");
				if (token == NULL)
					break;
				arguments->netflow_collector_addr = token;
				
				token = strtok(NULL, ":");
				if (token == NULL)
					break;
				
				int i = 0;
				while(i < strlen(token)) {
					if(!isdigit(token[i]))
						error("Port has to be a number!\n", 1);
					i++;
				}
					
				arguments->netflow_collector_port = token;	
				
				break;
			case 'a':
				arguments->active_timer = str_to_int(optarg);
				break;
			case 'i':
				arguments->inactive_timer = str_to_int(optarg);
				break;
			case 'm':
				arguments->cache_size = str_to_int(optarg);
				break;
			case '?':
				error("Usage: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n", 1);
		}
	}
}
