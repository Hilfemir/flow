/*
 * ISA Project
 * 
 * File: utilities.h
 * Author: Michal Blazek
 * 
 * VUT FIT 2022
 * 
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

extern int flow_size;

/**
 * Prints the message to stderr
 * and terminates the program with given status code
 */
void error(char* message, int status);

/**
 * Converts given string to int
 * calls the error() function if str is not a number
 */
int str_to_int(char* str);

/**
 * Takes the seconds and microseconds from the timeval struct
 * and converts them to miliseconds and adds them
 * 
 * Returns timestamp in miliseconds
 */
uint32_t calculate_timestamp(struct timeval ts);
