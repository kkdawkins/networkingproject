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


#define ETHERNET_ARP_REQUEST 1
#define ETHERNET_ARP_RESPONSE 2
#define ETHERNET_ARP 0x806
#define ETHERNET_IP  0x800
#define IP_ICMP		0x01
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_RESPONSE  0
#define ARP_LEN 28
#define ETHER_ADDR_HDR 14
#define DESTUNREACHABLE 3
#define TIMEEXCEED 11
#define DESTPORTUNREACH 3
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/


pthread_t arpcleaner;
pthread_t pbcleaner;
struct sr_if* me;
struct packet_buffer* phead;
void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    	


    /* Add initialization code here! */
    
    // We need to initialize the cache here!
    pthread_create(&arpcleaner,NULL,&cleaner,NULL);
    //pthread_create(&pbcleaner, NULL,&packetbufferCleaner,NULL);
	init_arp_cache();
	init_packet_buffer();
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

void* packetbufferCleaner(void* thread){
	// We want the cleaner thread to infinitely clean the cache
	// Yes, I am actually making an infinite loop
	while(1)
	{
#ifdef DEBUG
#if ((DEBUG > 3) && (DEBUG < 5)) || DEBUG == 10
		printf("PacketBuffer Cleaner start.\n");
#endif
#endif
		packet_buffer_cleaner();
#ifdef DEBUG
#if ((DEBUG > 3) && (DEBUG < 5)) || DEBUG == 10

		printf("PacketBuffer Cleaner End.\n");
#endif
#endif		
		sleep(10); // 15 Second timer, per spec
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
	fprintf(stderr,"\nhave a problem\n");
	return NULL;
}




char* check_routing_table(uint32_t ip_dst,struct sr_instance* sr,struct sr_ethernet_hdr* eh_pkt,char* ifname,uint32_t* nextHopIp)
{
	printf("Entering the routing table %x",ip_dst);
	struct sr_rt* rt1 = sr->routing_table;
	int maxlength = 0;
	int Length = 0;
	while(rt1)
	{
		//printf("Loop!!");
		Length = LongestMask(rt1->mask.s_addr);
		if(((ip_dst & rt1->mask.s_addr) == (rt1->dest.s_addr & rt1->mask.s_addr)) && (Length >= maxlength))
		{
			
			maxlength = Length;
			*nextHopIp = rt1->gw.s_addr;
			unsigned char bytes[4];
			     bytes[0] = 	rt1->gw.s_addr & 0xFF;
				bytes[1] = (rt1->gw.s_addr >> 8) & 0xFF;
				bytes[2] = (rt1->gw.s_addr >> 16) & 0xFF;
				bytes[3] = (rt1->gw.s_addr>> 24) & 0xFF;	  
				printf("\nin CRT next hop = %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]); 
				
			printf("--- Printing routing entry \n");
			sr_print_routing_entry(rt1);
			printf("---\n");
			memcpy(ifname,rt1->interface,sr_IFACE_NAMELEN); 
		}
		rt1 = rt1->next;
	}
	return ifname;
}

int LongestMask(uint32_t m)
{
	int l = 0;
	while(m > 0)
	{
		l++;
		m=m<<1;
	}
	return l;
}

void CreateARPRequest(struct sr_instance* sr,struct ip* ip_pkt1,
						char* ifname,unsigned char* ifhw1,uint32_t ifip,uint32_t nexthop)
{
	printf("\n\nCreating ARP Request!\n\n");
    printf("ifname %s\n", ifname);
    DebugMAC(ifhw1);
    unsigned char bytes[4];
    bytes[0] = 	ifip & 0xFF;
    bytes[1] = (ifip >> 8) & 0xFF;
    bytes[2] = (ifip >> 16) & 0xFF;
    bytes[3] = (ifip >> 24) & 0xFF;	
    printf("\nfip = %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]); 
     
	
	if(nexthop == 0){
		nexthop = ip_pkt1->ip_dst.s_addr;
	}
	
    //printf("next hop: %u\n",nexthop);
	struct sr_ethernet_hdr *eth;
	eth = malloc(sizeof(struct sr_ethernet_hdr));
	
	struct sr_arphdr *arp;
	arp = malloc(sizeof(struct sr_arphdr));
	
	int pktLen = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
	
	uint8_t* packet;
	packet = malloc(pktLen);
	
	memcpy(eth->ether_shost, ifhw1, ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERNET_ARP);
	
	memcpy(arp->ar_sha, ifhw1, ETHER_ADDR_LEN);
	arp->ar_sip = ifip;
	
	arp->ar_tha[0] = 0x00;
	arp->ar_tha[1] = 0x00;
	arp->ar_tha[2] = 0x00;
	arp->ar_tha[3] = 0x00;
	arp->ar_tha[4] = 0x00;
	arp->ar_tha[5] = 0x00;
	
	eth->ether_dhost[0] = 0xFF;
	eth->ether_dhost[1] = 0xFF;
	eth->ether_dhost[2] = 0xFF;
	eth->ether_dhost[3] = 0xFF;
	eth->ether_dhost[4] = 0xFF;
	eth->ether_dhost[5] = 0xFF;
	
	
	arp->ar_tip = nexthop;
	arp->ar_hrd = htons(ARPHDR_ETHER);
	arp->ar_hln = 6;
	arp->ar_op = htons(ARP_REQUEST);
	arp->ar_pln = 4;
	arp->ar_pro = htons(ETHERNET_IP);
	memcpy(packet, eth, ETHER_ADDR_HDR);
	memcpy(packet + sizeof(struct sr_ethernet_hdr), arp, ARP_LEN);
	sr_send_packet(sr, packet, pktLen, ifname);
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

    //uint16_t calc_icmp_cs = (ip_sum_calc(buff1,(uint8_t*)icmp_buf));

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

// FORWARD THE PACKET IF DESTINATION IS NOT OUR ROUTER
void packet_forward(struct sr_instance* sr,struct sr_ethernet_hdr* eh_pkt,struct ip* ip_pkt1,
					uint8_t* packet,unsigned int len,char* interface)
{
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	printf("----Packet forwarding>>>>>\n");
#endif
#endif
	char ifname[sr_IFACE_NAMELEN]; // through which forwarding is done
	int checksum = ntohs(ip_pkt1->ip_sum); // ZERO'ig out Checksum to cal 
	ip_pkt1->ip_sum = 0;
	uint8_t* hw = (uint8_t*)malloc(ETHER_ADDR_LEN);
	//sr->arp_cc = NULL;
	//uint8_t* pkt1 = (uint8_t*)malloc(len);
    	uint16_t calc_checksum_ip = (ip_sum_calc(sizeof(struct ip),(uint8_t*)ip_pkt1));
    	uint32_t* nexthop=(uint32_t*)malloc(sizeof(uint32_t));
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	printf("The calculated IP Checksum of the forwarding packet is %d\n",calc_checksum_ip);
	//return;
#endif
#endif
	if(calc_checksum_ip != checksum)
    {

#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10

fprintf(stderr, "Checksum error.The calculated checksum does not match with the packet's checksum which is %d",checksum);
return;
#endif
#endif
    }
	//check in the routing table to find the next destination
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	printf("\n Going to check the if name and the next hop address \n");
#endif
#endif
	char* if1 = check_routing_table(ip_pkt1->ip_dst.s_addr,sr,eh_pkt,ifname,nexthop);
	memcpy(ifname,if1,sr_IFACE_NAMELEN);
	//unsigned char* ifhw1 = Get_Router_Interface(ifname,sr);
	uint32_t ifip = Get_Router_Interface(ifname,sr)->ip;

		struct sr_if* interface_temp = Get_Router_Interface(ifname, sr);
		unsigned char* ifhw1   = interface_temp->addr;
	//	uint32_t outer_host_ip = interface_temp->ip;


	memcpy(eh_pkt->ether_shost,ifhw1,ETHER_ADDR_LEN);
	//constructing IP Packet
	ip_pkt1->ip_ttl=ip_pkt1->ip_ttl-1;
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10	
	printf("\n The current ttl count is %x \n",ip_pkt1->ip_ttl);
#endif
#endif
	ip_pkt1->ip_sum = htons(ip_sum_calc(sizeof(struct ip),(uint8_t*)ip_pkt1));
	
#ifdef DEBUG
#if ((DEBUG > 2) && (DEBUG < 4)) || DEBUG == 10
	uint16_t check = ip_pkt1->ip_sum;
	printf("\n The calculated IP Checksum of the forwarding packet is %d \n",check);
#endif
#endif
	arp_cache_add(ip_pkt1->ip_src.s_addr,eh_pkt->ether_shost);
	//If destination address present in arpcache, send the packet accordingly.
	//PrintEntriesInArpCache();

	// DUMPING ARP CACHE TO SEE THE ENTRIES
	dumparpcache();
	   				// IF NOT PRESENT IN CACHE DO PACKETBUFFER AND ARPREQUEST 
	if(check_arp_cache(ip_pkt1->ip_dst.s_addr) == 0) 
	{
		memcpy(eh_pkt->ether_shost,ifhw1,ETHER_ADDR_LEN);
		memcpy(packet,eh_pkt,sizeof(struct sr_ethernet_hdr));
		memcpy(packet+sizeof(struct sr_ethernet_hdr),ip_pkt1,sizeof(struct ip));
		printf("Not present in the cache");
		packet_buffer_add(packet,len,ip_pkt1);	// IMPLEMENT PACKETBUFFER
		printf("invoking arp request function");	// IMPLEMENT ARPREQUEST AND SEND THE PACKET

		CreateARPRequest(sr,ip_pkt1,ifname,ifhw1,ifip,*nexthop);
	}
	else 
	{					// IF PRESENT IN ARP CACHE SEND THE PACKET TO THE DEST
			 printf("Hurray I have received ICMP Echo Response!!");
			 hw = get_hardware_addr(ip_pkt1->ip_dst.s_addr);
			 struct sr_ethernet_hdr* eh = eh_pkt;
			 memcpy(eh->ether_shost,ifhw1,ETHER_ADDR_LEN);
			 memcpy(eh->ether_dhost,hw,ETHER_ADDR_LEN);
			 memcpy(packet,eh,sizeof(struct sr_ethernet_hdr));
			 sr_send_packet(sr,packet,len,ifname);
	 }
	return;
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
    printf("--------Start ARP Request\n");
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
	
	struct sr_if* myinterface;


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

	myinterface = Get_Router_Interface(interface, sr);
	

	eth_reply->ether_shost[0] = myinterface->addr[0];
	eth_reply->ether_shost[1] = myinterface->addr[1];
	eth_reply->ether_shost[2] = myinterface->addr[2];
	eth_reply->ether_shost[3] = myinterface->addr[3];
	eth_reply->ether_shost[4] = myinterface->addr[4];
	eth_reply->ether_shost[5] = myinterface->addr[5];


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
	printf("\nARP REPLY PACKET info ....\n");
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
    printf("Interface %s\n", interface);	
	printf("------End ARP Reply \n\n");
#endif	
#endif

	
	int ret = sr_send_packet(sr, buffer, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), interface);
	if(ret < 0){
		fprintf(stderr, "sr_send_packet failed.\n");
		exit(-1);
	}


	return 1;
}


void ProcessQeuedPackets(struct sr_instance* sr, struct sr_ethernet_hdr *eth, uint32_t ip, char *interface){
	uint8_t* hwaddr = NULL;
	struct pb_entry* pb = NULL;
	struct sr_ethernet_hdr *foo = malloc(sizeof(struct sr_ethernet_hdr));
	if(check_arp_cache(ip) == 1){
		hwaddr = get_hardware_addr(ip);
	}
	
	pb = packet_buffer_retrieve(ip);
	
	if(hwaddr == NULL || pb == NULL){
		fprintf(stderr,"Failed to retrieve hw addr or packet from buffers.\n");
		return;
	}
	
	memcpy(pb->packet, hwaddr, ETHER_ADDR_LEN);
	
	memcpy(foo, pb->packet, sizeof(struct sr_ethernet_hdr));
	
	printf("process interface  %s\n", interface);
	DebugMAC(foo->ether_shost);
	printf("\n");
	
	
	sr_send_packet(sr, pb->packet, pb->len, interface);
	
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
			if(ntohs(arp->ar_op) == ETHERNET_ARP_REQUEST){
				if(is_my_interface(arp->ar_tip) == 0){
					// The packet was for me (or one of my interfaces), so I can reply
					printf("3939 ARP request (self)\n");
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
			}
			else if(ntohs(arp->ar_op) == ETHERNET_ARP_RESPONSE){
				printf("\n\n3939Got ARP Response\n\n");
				
				arp_cache_add(arp->ar_sip, arp->ar_sha);
				
				ProcessQeuedPackets(sr, eth, arp->ar_sip, interface);
				
				// add to arp cache
				// process the stored packet
			}
		}else if(ntohs(eth->ether_type) == ETHERNET_IP){
            printf("3939 IP Packet\n");
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
					packet_forward(sr,eth,ipPkt,packet,len,interface);
				}
				else if(icmp->type == ICMP_ECHO_RESPONSE && (is_my_interface(ipPkt->ip_dst.s_addr) == 1)){
					printf("Got an ICMP Echo RESPONSE!\n");
					packet_forward(sr,eth,ipPkt,packet,len,interface);
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



void PacketError(struct sr_instance* sr,struct sr_ethernet_hdr* eth, struct ip* ipPkt, uint8_t* packet,unsigned int len,char* interface,int type,int code){
	struct sr_icmphdr* newicmp = malloc(sizeof(struct sr_icmphdr));
	struct sr_ethernet_hdr* neweth = malloc(sizeof(struct sr_ethernet_hdr));
	struct sr_if* myinterface = Get_Router_Interface(interface, sr);
	struct ip* origIP = malloc(sizeof(struct ip));
	memcpy(origIP, ipPkt, sizeof(struct ip));
	
	int newLen = 2*sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_icmphdr) + 8;
	
	uint8_t* newPacket = malloc(newLen);
	
	// set up new ethernet header
	memcpy(neweth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
	memcpy(neweth->ether_shost, myinterface->addr, ETHER_ADDR_LEN);
	//memcpy(neweth->ether_type, eth->ether_type, sizeof(uint16_t));
	neweth->ether_type = eth->ether_type;
	
	memcpy(newPacket, neweth, sizeof(struct sr_ethernet_hdr));
	
	// setup new IP packet
	uint32_t temp = ipPkt->ip_src.s_addr;
	ipPkt->ip_src.s_addr = myinterface->ip;
	ipPkt->ip_dst.s_addr = temp;
	
	ipPkt->ip_ttl = 200;
	ipPkt->ip_len = htons(newLen - sizeof(struct sr_ethernet_hdr));
	ipPkt->ip_p = IP_ICMP;
	ipPkt->ip_sum = 0;
	ipPkt->ip_sum = htons(ip_sum_calc(sizeof(struct ip), (uint8_t *)ipPkt));
	
	memcpy(newPacket + sizeof(struct sr_ethernet_hdr), ipPkt, sizeof(struct ip));
	
	newicmp->type = type;
	newicmp->code = code;
	newicmp->id = 0;
	newicmp->seq_no = 0;
	newicmp->checksum = 0;
	newicmp->checksum = htons(ip_sum_calc(sizeof(struct sr_icmphdr), (uint8_t *)newicmp));
	
	memcpy(newPacket + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), newicmp, sizeof(struct sr_icmphdr));
	memcpy(newPacket + sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmphdr), origIP, sizeof(struct ip));
	memcpy(newPacket+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmphdr)+sizeof(struct ip),packet+sizeof(struct ip)+sizeof(struct sr_ethernet_hdr),8);
	
	sr_send_packet(sr, newPacket, newLen, interface);

}
















