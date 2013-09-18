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

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



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

/* structure to hold the ipv4 header info */
typedef struct ipv4_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
uint8_t iphl:4,
uint8_t version:4; 
#elif defined (__BIG_ENDIAN_BITFIELD)
uint8_t version:4,
uint8_t iphl:4;
#else
#endif
uint8_t ver : 4; //Ip version
uint8_t iphl : 4; //Internet Header Length
uint8_t tos : 8; //Type Of Service
uint16_t len : 16; //Total Length
uint16_t ident : 16; //Identification
uint8_t flags : 3; //Flags
uint16_t offset: 13; //Fragment Offset:
uint8_t ttl : 8; //Time To Live
uint8_t proto : 8; //Protocol
uint16_t cksum : 16; //checksum
uint32_t src; //Source Address
uint32_t dest; //Destination Address
} __attribute__((packed)) IPV4_HEADER;


IPV4_HEADER  *ipv4_hdr = calloc(1,sizeof(IPV4_HEADER)); //Declares a struct of type IPV4_HEADER

memcpy(ipv4_hdr, packet, sizeof(IPV4_HEADER));

//ipv4_hdr = (IPV4_HEADER*)&packet;


	printf("*** -> Received packet of length %d \n",len);
	
/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 */
/// The Following will print out the translated datagram
printf("Version : %d \n", ipv4_hdr->ver);
printf("IP Header Length : %d \n", ipv4_hdr->iphl);
printf("Type of Service : %d \n", ipv4_hdr->tos);
printf("Size : %d \n", ipv4_hdr->len);
printf("Identification : %d \n", ipv4_hdr->ident);
printf("Flags : %x \n", ipv4_hdr->flags);
printf("Offset : %d \n", ipv4_hdr->offset);
printf("TTL : %d \n", ipv4_hdr->ttl);
printf("Protocol : %d \n", ipv4_hdr->proto);
printf("Source IP Addr : %d \n", ipv4_hdr->src);
//printf("Dest IP Addr : %x \n", ipv4_hdr->dest);

}
