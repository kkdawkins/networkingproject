/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

struct sr_if* me;

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    	


    /* Add initialization code here! */
    
    // We need to initialize the cache here!
	init_arp_cache();
} /* -- sr_init -- */



int isBroadcast(uint8_t *destMac){
    if((destMac[0] == 0xFF) &&
        (destMac[1] == 0xFF) &&
        (destMac[2] == 0xFF) &&
        (destMac[3] == 0xFF) &&
        (destMac[4] == 0xFF) &&
        (destMac[5] == 0xFF)){
        return 1;
    }else{
        return 0;
    }
}


int isARP(uint16_t type){
	if(type == 0x0806){
		return 1;
	}
	else{
	return 0;}
}

struct sr_ethernet_hdr* recieve_eth_header(uint8_t *packet){
		struct sr_ethernet_hdr* eth;	//Ethernet object
		eth = malloc(sizeof(struct sr_ethernet_hdr));
		memcpy(eth,packet,sizeof(struct sr_ethernet_hdr));
		printf("destination ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

		printf("Source ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		
		return eth;
}

struct sr_arphdr* recieve_arp_request(uint8_t *packet){

	struct sr_arphdr* arp;		//ARP object

	// Create the ARP struct
	arp = malloc(sizeof(struct sr_arphdr));
	memcpy(arp, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_arphdr));

	printf("Hardware type = 0x%02x\n",ntohs(arp->ar_hrd));
	printf("Protocol type = 0x%02x\n",ntohs(arp->ar_pro));
	printf("Hardware Size = %x\n",arp->ar_hln);
	printf("Protocol Size = %x\n",arp->ar_pln);
	printf("ARP opcode = 0x%02x\n",ntohs(arp->ar_op));
	printf("Sender MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_sha[0],arp->ar_sha[1],arp->ar_sha[2],arp->ar_sha[3],arp->ar_sha[4],arp->ar_sha[5]);

/* Calculating IP */
    unsigned char bytes[4];
    bytes[0] = 	arp->ar_sip & 0xFF;
    bytes[1] = (arp->ar_sip >> 8) & 0xFF;
    bytes[2] = (arp->ar_sip >> 16) & 0xFF;
    bytes[3] = (arp->ar_sip >> 24) & 0xFF;	
    printf("Sender IP address = %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]); 

	printf("Target MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_tha[0],arp->ar_tha[1],arp->ar_tha[2],arp->ar_tha[3],arp->ar_tha[4],arp->ar_tha[5]);
	
	
	
    unsigned char bytes1[4];
    bytes1[0] = arp->ar_tip & 0xFF;
    bytes1[1] = (arp->ar_tip >> 8) & 0xFF;
    bytes1[2] = (arp->ar_tip >> 16) & 0xFF;
    bytes1[3] = (arp->ar_tip >> 24) & 0xFF;	
    printf("Target IP address = %d.%d.%d.%d\n", bytes1[0], bytes1[1], bytes1[2], bytes1[3]);
    
	
	return arp;    
}


int generate_arp_reply(struct sr_instance* sr, struct sr_ethernet_hdr* eth, struct sr_arphdr* arp, char *interface){

	printf("ARP REPLY PACKET info ....\n");

	struct sr_ethernet_hdr* eth_reply;	//Ethernet reply object
	struct sr_arphdr* arp_reply;		//ARP reply object
	eth_reply = malloc(sizeof(struct sr_ethernet_hdr));
	arp_reply = malloc(sizeof(struct sr_arphdr));
// filling destination 
	eth_reply->ether_dhost[0] = eth->ether_shost[0];
	eth_reply->ether_dhost[1] = eth->ether_shost[1];
	eth_reply->ether_dhost[2] = eth->ether_shost[2];
	eth_reply->ether_dhost[3] = eth->ether_shost[3];
	eth_reply->ether_dhost[4] = eth->ether_shost[4];
	eth_reply->ether_dhost[5] = eth->ether_shost[5];
	printf("Destination ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",eth_reply->ether_dhost[0],eth_reply->ether_dhost[1],eth_reply->ether_dhost[2],
																			eth_reply->ether_dhost[3],eth_reply->ether_dhost[4],eth_reply->ether_dhost[5]);

	eth_reply->ether_shost[0] = me->addr[0];
	eth_reply->ether_shost[1] = me->addr[1];
	eth_reply->ether_shost[2] = me->addr[2];
	eth_reply->ether_shost[3] = me->addr[3];
	eth_reply->ether_shost[4] = me->addr[4];
	eth_reply->ether_shost[5] = me->addr[5];
	printf("Source ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",eth_reply->ether_shost[0],eth_reply->ether_shost[1],eth_reply->ether_shost[2],
																			eth_reply->ether_shost[3],eth_reply->ether_shost[4],eth_reply->ether_shost[5]);	

	eth_reply->ether_type = eth->ether_type;
	printf("Type: 0x%02x\n",ntohs(eth_reply->ether_type));
	
	arp_reply->ar_hrd = arp->ar_hrd;
	printf("Hardware type = 0x%02x\n",ntohs(arp_reply->ar_hrd));

	arp_reply->ar_pro = arp->ar_pro;
	printf("Protocol type = 0x%02x\n",ntohs(arp_reply->ar_pro));

	arp_reply->ar_hln = arp->ar_hln;
	printf("Hardware Size = %x\n",arp_reply->ar_hln);
	
	arp_reply->ar_pln = arp->ar_pln;
	printf("Protocol Size = %x\n",arp_reply->ar_pln);

	arp_reply->ar_op = 0x0200;
	printf("ARP opcode = 0x%02x\n",ntohs(arp_reply->ar_op));


	// Sender MAC address
	arp_reply->ar_sha[0] = me->addr[0];
	arp_reply->ar_sha[1] = me->addr[1];
	arp_reply->ar_sha[2] = me->addr[2];
	arp_reply->ar_sha[3] = me->addr[3];
	arp_reply->ar_sha[4] = me->addr[4];
	arp_reply->ar_sha[5] = me->addr[5];
	printf("Sender MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",arp_reply->ar_sha[0],arp_reply->ar_sha[1],arp_reply->ar_sha[2],arp_reply->ar_sha[3],arp_reply->ar_sha[4],arp_reply->ar_sha[5]);
	
	
	// Sender IP address
	arp_reply->ar_sip = arp->ar_tip;
	unsigned char bytes3[4];
    	bytes3[0] = arp_reply->ar_sip & 0xFF;
 	bytes3[1] = (arp_reply->ar_sip >> 8) & 0xFF;
    	bytes3[2] = (arp_reply->ar_sip >> 16) & 0xFF;
    	bytes3[3] = (arp_reply->ar_sip >> 24) & 0xFF;	
    	printf("Sender IP address = %d.%d.%d.%d\n", bytes3[0], bytes3[1], bytes3[2], bytes3[3]);
    	
    
	
	// Target MAC address
	arp_reply->ar_tha[0] = arp->ar_sha[0];
	arp_reply->ar_tha[1] = arp->ar_sha[1];
	arp_reply->ar_tha[2] = arp->ar_sha[2];
	arp_reply->ar_tha[3] = arp->ar_sha[3];
	arp_reply->ar_tha[4] = arp->ar_sha[4];
	arp_reply->ar_tha[5] = arp->ar_sha[5];
	printf("Target MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",arp_reply->ar_tha[0],arp_reply->ar_tha[1],arp_reply->ar_tha[2],arp_reply->ar_tha[3],arp_reply->ar_tha[4],arp_reply->ar_tha[5]);
	
	// Target IP address
	arp_reply->ar_tip = arp->ar_sip;
	unsigned char bytes2[4];
    	bytes2[0] = arp_reply->ar_tip & 0xFF;
 	bytes2[1] = (arp_reply->ar_tip >> 8) & 0xFF;
    	bytes2[2] = (arp_reply->ar_tip >> 16) & 0xFF;
    	bytes2[3] = (arp_reply->ar_tip >> 24) & 0xFF;	
    	printf("Target IP address = %d.%d.%d.%d\n", bytes2[0], bytes2[1], bytes2[2], bytes2[3]);
	
	
	uint8_t *buffer;
	buffer = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
	
	memcpy(buffer, eth_reply, sizeof(struct sr_ethernet_hdr));
	memcpy(buffer + sizeof(struct sr_ethernet_hdr), arp_reply, sizeof(struct sr_arphdr));
	
	//printf("Size of packet I am sending %d\n", sizeof(buffer));
	
	int ret = sr_send_packet(sr, buffer, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), interface);
	if(ret < 0){
		fprintf(stderr, "sr_send_packet failed.\n");
		exit(-1);
	}	
	
	return 1;
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
	
	me = NULL;
    me = sr_get_interface(sr,"eth0");
    if(me == NULL){
    	fprintf(stderr,"Failed to discover self.\n");
    	exit(-1);
    }
	
	struct sr_ethernet_hdr* eth = recieve_eth_header(packet);
	struct sr_arphdr* arp = recieve_arp_request(packet);
	
	if(isBroadcast(eth->ether_dhost)){
		if(isARP(ntohs(eth->ether_type))){
			if(me->ip == arp->ar_tip){
				generate_arp_reply(sr, eth, arp, interface);
			}
		}else{

			/* Code for IP packet */

			printf("Broadcast but not ARP\n");
			return;
		}
	}

}
