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

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



int isBroadcast(int *destMac){
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

int* destMac = malloc(6*sizeof(int));

memcpy(destMac, packet, 6*sizeof(int));

//ipv4_hdr = (IPV4_HEADER*)&packet;
    if(isBroadcast(destMac)){
        
        printf("Recieved Broadcast!\n");
    }else{
        printf("did NOT recieve broadcast!\n");
    }

	printf("*** -> Received packet of length %d \n",len);
	
/* end sr_ForwardPacket */


}
