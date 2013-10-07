#include "sr_router.h"
#include <stdlib.h>
#include <string.h>
typedef int bool;
#define true 1
#define false 0

#undef PBDEBUG
#ifdef DEBUG
#if ((DEBUG > 3) && (DEBUG < 5)) || DEBUG == 10
#define PBDEBUG
#endif
#endif

/*
* Implementation of packet buffer
* By: Kevin Dawkins and Karan Chadha
*/

struct pb_entry *pb_root;

bool init_packet_buffer(){
	pb_root = NULL;
#ifdef PBDEBUG
	printf("Packet buffer has been initialized!\n");
#endif

	return true;
}

void packet_buffer_cleaner(){
	struct pb_entry *curr;
	struct pb_entry *temp;
	struct pb_entry *lookahead;
#ifdef PBDEBUG
	printf("Packet buffer is being cleaned!\n");
#endif	
	curr = pb_root;
	if(curr == NULL){
		return;
	}
	
	// Clean out the root
	while((curr != NULL) && (curr->dirty == 1)){
		temp = curr;
		curr = curr->next;
		free(temp);
		pb_root = curr;
		//curr = curr->next;
	}
	
	if(pb_root == NULL){
		return; // this is if there was only 1 entry in cache, and got deleted
	}
	
	// scan the rest, need the lookahead, curr was checked above
	lookahead = curr->next;
	while(lookahead != NULL){
		if(lookahead->dirty == 1){
			if(lookahead->next == NULL)
			{
				temp = lookahead;
				curr->next = NULL;
				free(temp);
			}
			else{
				temp = lookahead;
				lookahead = lookahead->next;
				free(temp);
				curr->next = lookahead; // this, will increment us because we are moving lookahead
			}
		}else{
			lookahead = lookahead->next;
			curr = curr->next;
		}
	}
}


struct pb_entry* packet_buffer_retrieve(uint32_t ipaddr){
	struct pb_entry *curr = pb_root;
	
	if(curr == NULL){
		return NULL;
	}
	
	while(curr != NULL){
		if((curr->ipPkt->ip_dst.s_addr == ipaddr) && (curr->dirty == 0)){
			curr->dirty = 1;
			return curr;
		}
		curr = curr->next;
	}
	return NULL;
}


bool packet_buffer_add(uint8_t* pkt, unsigned int len, struct ip *ipPkt){
	struct pb_entry *node = malloc(sizeof(struct pb_entry));
	
	node->packet = malloc(len);
	memcpy(node->packet, pkt, len);
	
	//node->packet = pkt;
	node->len = len;
	node->ipPkt = ipPkt;
	node->dirty = 0;
	node->next = NULL;
	
	struct pb_entry *curr = pb_root;
	
	if(curr == NULL){
		pb_root = node;
	}else{
		while(curr->next != NULL){
			curr = curr->next;
		}
		curr->next = node;
	}
	
#ifdef PBDEBUG
	printf("Packet successfully added to packet buffer!\n");
#endif
	
	return true;
}


