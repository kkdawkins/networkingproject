/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * authors: Kevin Dawkins and Karan Chadha
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. TESTING MERGEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
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

/*
*	How debug works
*	Debug 0 -> off
*	Debug 1 -> Eth and ARP only
*	Debug 2 -> Eth and IP only
*	Debug 3 -> ?
*
*	Debug 10 -> ALL On
*	
*	Happy Debugging! :-)
*/

#define DEBUG 10

#define ETHERNET_ARP 0x806
#define ETHERNET_IP  0x800
#define IP_ICMP		0x01
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_RESPONSE  0
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

int is_my_interface(uint32_t ip){
	// if it is one of my own ill return 0
	// if we need to packet forward, ill return 1
}


struct ip*	recieve_ip_packet(uint8_t *packet){
	struct ip* ippkt;
	ippkt = malloc(sizeof(struct ip));
	memcpy(ippkt, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip));
	//printf("Header Length = %d\n",ippkt->ip_hl);
	//printf("Version = %d\n",ippkt->ip_v);
	if (ippkt->ip_v!=4){					// CHECK FOR IPV4 PACKET
	fprintf(stderr,"Failed to discover self.\n");
    	exit(-1);
   	 }
		



	return ippkt;
}

void icmp_request(){

}

void packet_forward(){
}




struct sr_ethernet_hdr* recieve_eth_header(uint8_t *packet){
		struct sr_ethernet_hdr* eth;	//Ethernet object
		eth = malloc(sizeof(struct sr_ethernet_hdr));
		memcpy(eth,packet,sizeof(struct sr_ethernet_hdr));
#ifdef DEBUG
		printf("destination ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",
				eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],
				eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

		printf("Source ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],
			eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		printf("Ethernet type %x\n",eth->ether_type);
#endif		
		return eth;
}

struct sr_arphdr* recieve_arp_request(uint8_t *packet){

	struct sr_arphdr* arp;		//ARP object

	// Create the ARP struct
	arp = malloc(sizeof(struct sr_arphdr));
	memcpy(arp, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_arphdr));
#ifdef DEBUG
#if ((DEBUG > 0) && (DEBUG < 2)) || DEBUG == 10
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
    
	printf("------End ARP Request \n\n");
#endif
#endif
	return arp;    
}


int generate_arp_reply(struct sr_instance* sr, struct sr_ethernet_hdr* eth, struct sr_arphdr* arp, char *interface){



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


	eth_reply->ether_shost[0] = me->addr[0];
	eth_reply->ether_shost[1] = me->addr[1];
	eth_reply->ether_shost[2] = me->addr[2];
	eth_reply->ether_shost[3] = me->addr[3];
	eth_reply->ether_shost[4] = me->addr[4];
	eth_reply->ether_shost[5] = me->addr[5];


	eth_reply->ether_type = eth->ether_type;
	
	arp_reply->ar_hrd = arp->ar_hrd;

	arp_reply->ar_pro = arp->ar_pro;

	arp_reply->ar_hln = arp->ar_hln;
	
	arp_reply->ar_pln = arp->ar_pln;

	arp_reply->ar_op = 0x0200;

	// Sender MAC address
	arp_reply->ar_sha[0] = me->addr[0];
	arp_reply->ar_sha[1] = me->addr[1];
	arp_reply->ar_sha[2] = me->addr[2];
	arp_reply->ar_sha[3] = me->addr[3];
	arp_reply->ar_sha[4] = me->addr[4];
	arp_reply->ar_sha[5] = me->addr[5];	
	
	// Sender IP address
	arp_reply->ar_sip = arp->ar_tip;
	
   
	
	// Target MAC address
	arp_reply->ar_tha[0] = arp->ar_sha[0];
	arp_reply->ar_tha[1] = arp->ar_sha[1];
	arp_reply->ar_tha[2] = arp->ar_sha[2];
	arp_reply->ar_tha[3] = arp->ar_sha[3];
	arp_reply->ar_tha[4] = arp->ar_sha[4];
	arp_reply->ar_tha[5] = arp->ar_sha[5];

	
	// Target IP address
	arp_reply->ar_tip = arp->ar_sip;
		
	
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
		
#ifdef DEBUG
#if ((DEBUG > 0) && (DEBUG < 2)) || DEBUG == 10	
	unsigned char bytes3[4];
    	bytes3[0] = arp_reply->ar_sip & 0xFF;
 	bytes3[1] = (arp_reply->ar_sip >> 8) & 0xFF;
    	bytes3[2] = (arp_reply->ar_sip >> 16) & 0xFF;
    	bytes3[3] = (arp_reply->ar_sip >> 24) & 0xFF;
    unsigned char bytes2[4];
    	bytes2[0] = arp_reply->ar_tip & 0xFF;
 	bytes2[1] = (arp_reply->ar_tip >> 8) & 0xFF;
    	bytes2[2] = (arp_reply->ar_tip >> 16) & 0xFF;
    	bytes2[3] = (arp_reply->ar_tip >> 24) & 0xFF;
	printf("ARP REPLY PACKET info ....\n");
    printf("Source ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth_reply->ether_shost[0],eth_reply->ether_shost[1],eth_reply->ether_shost[2],
			eth_reply->ether_shost[3],eth_reply->ether_shost[4],eth_reply->ether_shost[5]);
	printf("Destination ethernet address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth_reply->ether_dhost[0],eth_reply->ether_dhost[1],eth_reply->ether_dhost[2],
			eth_reply->ether_dhost[3],eth_reply->ether_dhost[4],eth_reply->ether_dhost[5]);	
	printf("Type: 0x%02x\n",ntohs(eth_reply->ether_type));
	printf("Hardware type = 0x%02x\n",ntohs(arp_reply->ar_hrd));
	printf("Protocol type = 0x%02x\n",ntohs(arp_reply->ar_pro));
	printf("Hardware Size = %x\n",arp_reply->ar_hln);
	printf("Protocol Size = %x\n",arp_reply->ar_pln);
	printf("ARP opcode = 0x%02x\n",ntohs(arp_reply->ar_op));
	printf("Sender MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			arp_reply->ar_sha[0],arp_reply->ar_sha[1],arp_reply->ar_sha[2],
			arp_reply->ar_sha[3],arp_reply->ar_sha[4],arp_reply->ar_sha[5]);
    	printf("Sender IP address = %d.%d.%d.%d\n", bytes3[0], bytes3[1], bytes3[2], bytes3[3]);
	printf("Target MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			arp_reply->ar_tha[0],arp_reply->ar_tha[1],arp_reply->ar_tha[2],
			arp_reply->ar_tha[3],arp_reply->ar_tha[4],arp_reply->ar_tha[5]);
    printf("Target IP address = %d.%d.%d.%d\n", bytes2[0], bytes2[1], bytes2[2], bytes2[3]);	
	printf("------End ARP Reply \n\n");
#endif	
#endif
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
	//struct sr_arphdr* arp = recieve_arp_request(packet);
	
//	if(isBroadcast(eth->ether_dhost)){
		if(ntohs(eth->ether_type) == ETHERNET_ARP){
			struct sr_arphdr* arp = recieve_arp_request(packet);
			if(me->ip == arp->ar_tip){
				// The packet was for me, so I can reply
				generate_arp_reply(sr, eth, arp, interface);
			}else{
				// The packet was for someone else, so I should 
				// 1. Check the cache
				// 2. If not in cache, broadcast to the rest to figure out
				if(check_arp_cache(arp->ar_tip) == 1){
					// it is in the cache
				}else{
					// need to send a broadcast message
					printf("Recieved a packet that was not in cache\n");
				}
			}
		}else if(ntohs(eth->ether_type) == ETHERNET_IP){
			struct ip* ipPkt = recieve_ip_packet(packet);
			printf("Got an IP Packet (with version %x)! With IP opcode %x\n\n", ipPkt->ip_v,ipPkt->ip_p);
			if(ipPkt->ip_p == IP_ICMP){
				printf("It is an ICMP!\n");
				struct sr_icmphdr* icmp = malloc(sizeof(struct sr_icmphdr));
				memcpy(icmp, packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), sizeof(struct sr_icmphdr));
				

				// TODO check for whether the destination address is one of the router's addresses


				
				if(icmp->type == ICMP_ECHO_REQUEST  /* TODO YES */){
					printf("Got an ICMP Echo Request!\n");
					icmp_request();
				}
				else if(icmp->type == ICMP_ECHO_REQUEST  /* TODO NO */){
					printf("Got an ICMP Echo Request!\n");
					packet_forward();
				}
				else if(icmp->type == ICMP_ECHO_RESPONSE  /* TODO NO */){
					printf("Got an ICMP Echo RESPONSE!\n");
					packet_forward();
				}
	/*			else if(ipPkt->ip_p == ETHERNET_TCP) {
		 //printf("TCP Protocol it is");
		 // TODO check for whether the destination address is one of the router's addresses
		 if(myIf == 0)
		 {
			 //printf("Oops!! Pinged the wrong IP Address!! You are gonna receive Port Unreachable");
			 PortUnreachable(sr,eh_pkt,ip_pkt,pck_buf,len,interface,3,3);
			 
		 }
		 else if(myIf != 0)
		 {
			packet_forward(sr,eh_pkt,ip_pkt,pck_buf,len,interface);
		 }
	 }*/
			}
		
		}else{

			/* Code for IP packet */

			printf("Not an ARP or IP Packet. opcode = %X\n\n",ntohs(eth->ether_type));
			return;
		}
//	}

}
