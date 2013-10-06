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
*	Debug 3 -> Eth and ICMP Request
*	Debug 4 -> ?
*
*	Debug 10 -> ALL On
*	
*	Happy Debugging! :-)
*/

#define DEBUG 1

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


pthread_t arpcleaner;
struct sr_if* me;

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    	


    /* Add initialization code here! */
    
    // We need to initialize the cache here!
    pthread_create(&arpcleaner,NULL,&cleaner,NULL);
	init_arp_cache();
} /* -- sr_init -- */


// The algorithm to calculate the IP checksum was taken from the internet
// Neither author claims to have created/designed this algorithm
// Reference: http://www.netfor2.com/ipsum.htm
/*
**************************************************************************
Function: ip_sum_calc
Description: Calculate the 16 bit IP sum.
***************************************************************************
*/

uint16_t ip_sum_calc(uint16_t len_ip_header, uint8_t buff[])
{
uint16_t word16;
uint32_t sum=0;
uint16_t i;
    
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for (i=0;i<len_ip_header;i=i+2){
		word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum = sum + (uint32_t) word16;	
	}
	
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum>>16)
	  sum = (sum & 0xFFFF)+(sum >> 16);

	// one's complement the result
	sum = ~sum;
	
return ((uint16_t) sum);
}



void* cleaner(void* thread)
{
	// We want the cleaner thread to infinitely clean the cache
	// Yes, I am actually making an infinite loop
	while(1)
	{
#ifdef DEBUG
#if ((DEBUG > 0) && (DEBUG < 2)) || DEBUG == 10
		printf("ARP Cleaner start.\n");
#endif
#endif
		arpCacheDeleter();
#ifdef DEBUG
#if ((DEBUG > 0) && (DEBUG < 2)) || DEBUG == 10
		dumparpcache();
		printf("ARP Cleaner End.\n");
#endif
#endif		
		sleep(15); // 15 Second timer, per spec
	}
}

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

int is_my_interface(uint32_t givenip){
	// if it is one of my own ill return 0
	// if we need to packet forward, ill return 1
	struct sr_if* curr = me;
	while(curr != NULL){
		if(curr->ip == givenip){
			return 0;
		}
		curr = curr->next;
	}
	
	return 1;
}

struct sr_if* Get_Router_Interface(char* interfaceName, struct sr_instance *sr){
	struct sr_if *curr;
	curr = sr->if_list;
	
	while(curr){
		if(strcmp(interfaceName, curr->name) == 0){
			return curr;
		}
		curr = curr->next;
	}
	
	return NULL;
}




struct ip*	recieve_ip_packet(uint8_t *packet){
	struct ip* ippkt;
	ippkt = malloc(sizeof(struct ip));
	memcpy(ippkt, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip));

	//printf("Header Length = %d\n",ippkt->ip_hl);
	//printf("Version = %d\n",ippkt->ip_v);
	if (ippkt->ip_v!=4){					// CHECK FOR IPV4 PACKET
	fprintf(stderr,"NOT A IPV4 PACKET.\n");
    	exit(-1);
   	 }
	return ippkt;
}

void icmp_request(struct sr_instance* sr, struct sr_ethernet_hdr* eth, struct ip* ipPkt, struct sr_icmphdr* icmp, char* interface, uint8_t *packet, unsigned int len){
	struct sr_if* myinterface;
	unsigned char *router_host_addr;
	uint32_t router_host_ip;
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	printf("---ICMP Request has been recieved---\n");
	printf("---Formulating ICMP Response---\n");
#endif
#endif
	if(is_my_interface(ipPkt->ip_dst.s_addr) == 0){
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
		printf("---ICMP for one of the router's interfaces---\n");
#endif
#endif
		myinterface = Get_Router_Interface(interface, sr);
		router_host_addr = myinterface->addr;
		router_host_ip = myinterface->ip;
	}
	
	uint16_t checksum = ntohs(ipPkt->ip_sum);
	
	ipPkt->ip_sum = 0; // The IP Checksum calc must be done with checksum = 0
	
	if((ip_sum_calc(sizeof(struct ip), (uint8_t*)ipPkt)) != checksum){
		fprintf(stderr,"Checksum validation failed.\n");
		return;
	}
	
	// First, we must build a new ethernet header packet
	struct sr_ethernet_hdr *eth_new = malloc(sizeof(struct sr_ethernet_hdr));
	eth_new->ether_type = htons(ETHERNET_IP);
	memcpy(eth_new->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_new->ether_shost, router_host_addr, ETHER_ADDR_LEN);
	memcpy(packet,eth_new, sizeof(struct sr_ethernet_hdr));
	
	//Now we must make a new IP Packet
	uint32_t temp = ipPkt->ip_src.s_addr;
	ipPkt->ip_src.s_addr = router_host_ip;
	ipPkt->ip_dst.s_addr = temp;
	ipPkt->ip_ttl = 0xFF;
	ipPkt->ip_sum = htons(ip_sum_calc(sizeof(struct ip), (uint8_t*)ipPkt));
	
	// place ip packet into the packet
	memcpy(packet+sizeof(struct sr_ethernet_hdr), ipPkt, sizeof(struct ip));

	int icmp_payload = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip) - sizeof(struct sr_icmphdr);
    int buff1 = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
    int buff2 = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr);
    uint8_t* icmp_buf = malloc(buff1);
    uint16_t icmp_checksum = ntohs(icmp->checksum);

    memcpy(icmp_buf,icmp,sizeof(struct sr_icmphdr));
    memcpy(icmp_buf+sizeof(struct sr_icmphdr),packet+buff2,icmp_payload);

    uint16_t calc_icmp_cs = (ip_sum_calc(buff1,(uint8_t*)icmp_buf));

    if(!(ip_sum_calc(buff1,(uint8_t*)icmp_buf)) == icmp_checksum)
    {
		fprintf(stderr,"Checksum validation failed.\n");
		return;
    }
    icmp->type = ICMP_ECHO_RESPONSE;
    memcpy(icmp_buf,icmp,sizeof(struct sr_icmphdr));
    icmp->checksum = htons(ip_sum_calc(buff1,(uint8_t*)icmp_buf));
    memcpy(icmp_buf,icmp,sizeof(struct sr_icmphdr));
    memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),icmp_buf,buff1);
    
    sr_send_packet(sr,packet,len,interface);//send the packet
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	printf("---ICMP Response has been sent---\n");
#endif
#endif
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
    me = sr->if_list;
    if(me == NULL){
    	fprintf(stderr,"Failed to discover self.\n");
    	exit(-1);
    }
	
	struct sr_ethernet_hdr* eth = recieve_eth_header(packet);
	//struct sr_arphdr* arp = recieve_arp_request(packet);
	
//	if(isBroadcast(eth->ether_dhost)){
		if(ntohs(eth->ether_type) == ETHERNET_ARP){
			struct sr_arphdr* arp = recieve_arp_request(packet);
			if(is_my_interface(arp->ar_tip) == 0){
				// The packet was for me (or one of my interfaces), so I can reply
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
			arp_cache_add(ipPkt->ip_src.s_addr, eth->ether_shost);
			if(ipPkt->ip_p == IP_ICMP){
				printf("It is an ICMP!\n");
				struct sr_icmphdr* icmp = malloc(sizeof(struct sr_icmphdr));
				memcpy(icmp, packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), sizeof(struct sr_icmphdr));				

				// TODO check for whether the destination address is one of the router's addresses


				if((icmp->type == ICMP_ECHO_REQUEST) && (is_my_interface(ipPkt->ip_dst.s_addr) == 0)){

					printf("Got an ICMP Echo Request!\n");
					icmp_request(sr, eth, ipPkt, icmp,interface, packet, len);
				}else if(icmp->type == ICMP_ECHO_REQUEST && (is_my_interface(ipPkt->ip_dst.s_addr) == 1)){
					printf("Got an ICMP Echo Request LETS DO PACKET FORWARD!\n");
					packet_forward();
				}
				else if(icmp->type == ICMP_ECHO_RESPONSE && (is_my_interface(ipPkt->ip_dst.s_addr) == 1)){
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
