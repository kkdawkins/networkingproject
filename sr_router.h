/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024



/*
*	How debug works
*	Debug 0 -> off
*	Debug 1 -> Eth and ARP only
*	Debug 2 -> Eth and IP only
*	Debug 3 -> Eth and ICMP Request
*	Debug 4 -> Eth and Packet Buffer
*
*	Debug 10 -> ALL On
*	
*	Happy Debugging! :-)
*/

#define DEBUG 1




/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
};

struct pb_entry{
	uint8_t *packet;
	struct ip* ipPkt;
	unsigned int len;
	struct pb_entry *next;
} __attribute__ ((packed)) ;

struct arp_entry{
    uint32_t            ip_addr;
    uint8_t             h_addr[ETHER_ADDR_LEN];
    struct timeval		creation;
    
    struct arp_entry*   next;
} arp_entry;

struct sr_icmphdr
{
      uint8_t type;                    
      uint8_t code;
      uint16_t checksum;
      uint16_t id;                                /*Identifier*/
      uint16_t seq_no;         /*Sequence Number*/
} __attribute__ ((packed)) ;

struct sr_icmpMessage
{
   uint8_t type;                    
   uint8_t code;
   uint16_t checksum;
   uint16_t empty;
   uint16_t nexthop;
} __attribute__ ((packed)) ;

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void* cleaner(void* thread);
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* -- sr_arpcache.c -- */
int init_arp_cache(); // Returns 1 on success
int check_arp_cache(uint32_t ip);  /* Will return:
                                    *   1  - Specified IP is in cache
                                    *   0  - Specified IP is not in cache
                                    */  
uint8_t* get_hardware_addr(uint32_t ip); /* Assumed called after check for saftey
                                          * Will return a pointer to a uint8_t array on success
                                          * Null on failure
                                          */
int arp_cache_add(uint32_t ip, uint8_t* hardware); /* Will return:
                                                    * 1 - Add success
                                                    * -1 - Table full
                                                    * -2 - Failure
                                                    */
void arpCacheDeleter();
void dumparpcache();

#endif /* SR_ROUTER_H */
