/*
 * ISA Project
 * 
 * File: utilities.c
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include "utilities.h"

void error(char* message, int status) {
	fprintf(stderr, message);
	exit(status);
}

int str_to_int(char* str) {
	char *ptr;
	int ret;
	
	ret = strtol(str, &ptr, 10);
	if (*ptr == '\0')
		return ret;
	else
		error("Could not convert string to int\n", 2);
}

uint32_t calculate_timestamp(struct timeval ts) {
	return (1000 * ts.tv_sec + ts.tv_usec / 1000);
}
