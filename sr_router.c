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
typedef unsigned long UINT32;
typedef struct ipv4_hdr_f1 {

UINT32 ver : 4; //Ip version
UINT32 iphl : 4; //Internet Header Length
UINT32 tos : 8; //Type Of Service
UINT32 len : 16; //Total Length
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    iphl:4,
                 version:4; 
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                 iphl:4;
#else
//#error  "Please fix <asm/byteorder.h>"
#endif

} __attribute__((packed)) IPV4_HDR_F1;
typedef struct ipv4_hdr_f2 {
UINT32 ident : 16; //Identification
UINT32 flags : 3; //Flags
UINT32 offset: 13; //Fragment Offset:
} __attribute__((packed)) IPV4_HDR_F2;
typedef struct ipv4_hdr_f3 {
UINT32 ttl : 8; //Time To Live
UINT32 proto : 8; //Protocol
UINT32 cksum : 16; //checksum
} __attribute__((packed)) IPV4_HDR_F3;
typedef struct ipv4_header {
IPV4_HDR_F1 f1;
IPV4_HDR_F2 f2;
IPV4_HDR_F3 f3;
UINT32 src; //Source Address
UINT32 dest; //Destination Address
} __attribute__((packed)) IPV4_HEADER;


IPV4_HEADER  *ipv4_hdr; //Declares a struct of type IPV4_HEADER

ipv4_hdr = (IPV4_HEADER*)&packet;


	printf("*** -> Received packet of length %d \n",len);
	
/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 */
/// The Following will print out the translated datagram
printf("Version : %d \n", ipv4_hdr->f1.ver);
printf("IP Header Length : %d \n", ipv4_hdr->f1.iphl);
printf("Type of Service : %d \n", ipv4_hdr->f1.tos);
printf("Size : %d \n", ipv4_hdr->f1.len);
printf("Identification : %d \n", ipv4_hdr->f2.ident);
printf("Flags : %x \n", ipv4_hdr->f2.flags);
printf("Offset : %d \n", ipv4_hdr->f2.offset);
printf("TTL : %d \n", ipv4_hdr->f3.ttl);
printf("Protocol : %d \n", ipv4_hdr->f3.proto);
printf("Source IP Addr : %d \n", ipv4_hdr->src);
//printf("Dest IP Addr : %x \n", ipv4_hdr.dest);

}
