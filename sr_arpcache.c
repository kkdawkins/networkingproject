#include "sr_router.h"
#include <stdlib.h>
/*
 * Implementation of the ARP cache
 * Kevin Dawkins and Karan Chadha
 */
#define DEBUG

struct arp_entry* root;

int init_arp_cache(){
	root = NULL;
	
	// We will do timer thread start here

#ifdef DEBUG
	printf("ARP Cache initialized!\n");
#endif
	return 1;
}

int check_arp_cache(uint32_t ip){
#ifdef DEBUG
	printf("Check: looking for: %d\n", ip);
#endif
	struct arp_entry* curr;
	
	curr = root;
	
	while(curr != NULL){
#ifdef DEBUG
		printf("\t found %d\n",curr->ip_addr);
#endif
		if(curr->ip_addr == ip){
			return 1;
		}
		curr = curr->next;
	}
    return 0;
}


/*
 * This function should be called AFTER check_arp_cache
 * Check the cache for a hit with the given IP addr
 */
uint8_t* get_hardware_addr(uint32_t ip){
    struct arp_entry* curr;

    curr = root;
#ifdef DEBUG
	printf("Get: looking for%d\n", ip);
#endif
    while(curr != NULL){
#ifdef DEBUG
	printf("\t Found: %d\n",curr->ip_addr);
#endif
        if(curr->ip_addr == ip){
            return curr->h_addr;
        }
        curr = curr->next;
    }

    return NULL;
}

int arp_cache_add(uint32_t ip, uint8_t* haddr){
    if(check_arp_cache(ip)){
        // It is already in the cache! 
        // We can either add it again, or update the timer...
        return 1; // For now just return
    }
#ifdef DEBUG
	printf("Added %d to ARP cache\n",ip);
#endif

    struct arp_entry* node = malloc(sizeof(struct arp_entry));
    node->ip_addr = ip;
    node->h_addr[0] = haddr[0];
    node->h_addr[1] = haddr[1];
    node->h_addr[2] = haddr[2];
    node->h_addr[3] = haddr[3];
    node->h_addr[4] = haddr[4];
    node->h_addr[5] = haddr[5];
    return 1;
}
