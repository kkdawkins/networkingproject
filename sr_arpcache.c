#include "sr_router.h"
#include <stdlib.h>
/*
 * Write stuff here
 */

struct arp_entry* root;

int init_arp_cache(){
	root = NULL;
	// For now this is hard coded
	struct arp_entry* node = malloc(sizeof(struct arp_entry));
	node->ip_addr = 1722912200;
	node->h_addr[0] = 0x32;
	node->h_addr[1] = 0xd6;
	node->h_addr[2] = 0xf8;
	node->h_addr[3] = 0xb4;
	node->h_addr[4] = 0x5d;
	node->h_addr[5] = 0xf7;
	
	
	root = node;
	
	return 1;
}

int check_arp_cache(uint32_t ip){
	printf("looking for: %d have %d\n", ip, root->ip_addr);
	if(root->ip_addr == ip){
		return 1;
	}
    return 1;
}

uint8_t* get_hardware_addr(uint32_t ip){
	if(root->ip_addr == ip){
		return root->h_addr;
	}
    return root->h_addr;
}

int arp_cache_add(uint32_t ip, uint8_t* haddr){
    return 1;
}
