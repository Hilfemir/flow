/*
 * ISA Project
 * 
 * File: argparse.h
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <unistd.h>

struct Arguments {
	char* input_file;
	char* netflow_collector_addr;
	char* netflow_collector_port;
	int active_timer;
	int inactive_timer;
	int cache_size;
};

/**
 * Function takes arguments from argv, processes them accordingly
 * and passes them to the Arguments structure
 */
void parse_arguments(int argc, char **argv, struct Arguments* arguments);
