#include "sr_router.h"
#include <stdlib.h>
/*
 * Implementation of the ARP cache
 * Kevin Dawkins and Karan Chadha
 */
#define ARPDEBUG
typedef int bool;
#define true 1
#define false 0


struct arp_entry* root;



bool timeCheck(struct timeval cacheCreationTime){
	struct timeval currentTime;
	gettimeofday (&currentTime, NULL);
	if((currentTime.tv_sec - cacheCreationTime.tv_sec) > 15){
		return true;
	}
	return false;
}


void arpCacheDeleter(){
	struct arp_entry* curr = NULL;
	struct arp_entry* temp = NULL; // the one to be deleted
	struct arp_entry* lookahead = NULL;
	
	curr = root;
	if(curr == NULL){
		return;
	}
	
	// Clean out the root
	while((curr != NULL) && (timeCheck(curr->creation) == true)){
		temp = curr;
		curr = curr->next;
		free(temp);
		root = curr;
	}
	
	if(root == NULL){
		return; // this is if there was only 1 entry in cache, and got deleted
	}
	
	// scan the rest, need the lookahead, curr was checked above
	lookahead = curr->next;
	while(lookahead != NULL){
		if(timeCheck(lookahead->creation) == true){
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

/*
* This function should only be called in debug mode
* so, guarding prints with debug is redundant.
*/
void dumparpcache(){
	struct arp_entry* curr;
	curr = root;
	printf("---Printing ARP Cache---\n");
	while(curr){
		printf("IP Addr %d : ", ntohl(curr->ip_addr));
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",curr->h_addr[0],curr->h_addr[1],curr->h_addr[2],curr->h_addr[3],curr->h_addr[4],curr->h_addr[5]);
		curr = curr->next;
	}
	printf("---End ARP Cache---\n");
}

int init_arp_cache(){
	root = NULL;
	
	// We will do timer thread start here

#ifdef ARPDEBUG
	printf("ARP Cache initialized!\n");
#endif
	return true;
}

bool check_arp_cache(uint32_t ip){
#ifdef ARPDEBUG
	printf("Check: looking for: %d\n", ip);
#endif
	struct arp_entry* curr;
	
	curr = root;
	
	while(curr != NULL){
#ifdef ARPDEBUG
		printf("\t found %d\n",curr->ip_addr);
#endif
		if(curr->ip_addr == ip){
			return true;
		}
		curr = curr->next;
	}
    return false;
}


/*
 * This function should be called AFTER check_arp_cache
 * Check the cache for a hit with the given IP addr
 */
uint8_t* get_hardware_addr(uint32_t ip){
    struct arp_entry* curr;

    curr = root;
#ifdef ARPDEBUG
	printf("Get: looking for%d\n", ip);
#endif
    while(curr != NULL){
#ifdef ARPDEBUG
	printf("\t Found: %d\n",curr->ip_addr);
#endif
        if(curr->ip_addr == ip){
            return curr->h_addr;
        }
        curr = curr->next;
    }

    return NULL;
}

/*
* Once again - assumed called AFTER check_arp_cache
*/
void updateARPCacheEntry(uint32_t ip){
	struct arp_entry *curr;
	struct timeval currtime;
	gettimeofday(&currtime, NULL);
	curr = root;
	while(curr != NULL){
		if(curr->ip_addr == ip){
			curr->creation = currtime;
			return;
		}	
	}
}

bool arp_cache_add(uint32_t ip, uint8_t* haddr){
	struct arp_entry* curr;
	struct timeval currtime;
	gettimeofday (&currtime, NULL);
    if(check_arp_cache(ip)){
        // The entry is already in the ARP cache, so we must update the timestamp
#ifdef ARPDEBUG
		printf("Already in ARP Cache, updating timestamp.\n");
#endif
        updateARPCacheEntry(ip);
        return true; // For now just return
    }
#ifdef ARPDEBUG
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
    
    node->creation = currtime;
    
    node->next = NULL;
    
	    
    if(root == NULL)
    {
    	root = node;	
    }else{
    	curr = root;
    	while(curr->next != NULL)
    	{
    		curr = curr->next;
    	}
    	curr->next = node;
    }
    
    return true;
}
