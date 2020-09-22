/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: long_pref_match(uint32_t ip_dst)
 * Scope:  Local
 *
 * This method is called when the router determines the packet received is
 * not for any of its interfaces and it needs to find the next hop entry
 * from the routing table.
 *
 * This function uses Longest Prefix Match to determine the next hop entry
 * which works as follows. The function loops over all entries in the routing
 * table and calculates the destination network using the netmask and then
 * applies the same netmask to the destination IP address and checks if they're
 * equal. If they are, it stores a pointer to the rt entry and records the
 * prefix length which is just the number of 1s in the binary representation
 * of the netmask.
 *
 * Finally, the pointer to the entry with the maximum prefix length is returned
 * as the next hop entry. If no entry is matched, the function returns NULL.
 *
 *---------------------------------------------------------------------*/

struct sr_rt * long_pref_match(struct sr_instance* sr,
        uint32_t ip_dst)
{
    struct sr_rt * rt_walker = sr->routing_table;
    int max_pref_len = 0;
    struct sr_rt * matched_entry = NULL;

    /* Iterate over all entries in routing table */
    while(rt_walker){
        /* Use logical AND to get destination network from destination */
        uint32_t dest_network = rt_walker->dest.s_addr & rt_walker->mask.s_addr;
        uint32_t dest_ip_net = ip_dst & rt_walker->mask.s_addr;
        uint32_t mask = ntohl(rt_walker->mask.s_addr);

        if (dest_network == dest_ip_net){
            /* Calculate prefix length */
            int len = 0;
            while(mask) {
                len += mask & 1;
                mask >>= 1;
            }
            /* Save entry with longest prefix */
            if (len > max_pref_len)
                matched_entry = rt_walker;
        }
        rt_walker = rt_walker->next;
    }

    return matched_entry;
}

/*---------------------------------------------------------------------
 * Method: create_arp_request(uint32_t target_ip,
                              uint8_t * packet,
                              unsigned int len,
                              char* iface)
 * Scope:  Local
 *
 * This method is called when the router a packet that is not intended for
 * itself but for a host contained in the router's routing table. The router
 * must now send an ARP request to determine the next-hop MAC address and
 * then forward the packet. This method creates an packet buffer then creates
 * packets in the order: Ethernet, ARP.
 *
 * Once a request is sent over the LAN, it is stored in the ARP cache and
 * repeatedly sent till timeout or arp reply. The packet argument along with
 * len refers to the packet received for which we need to send an ARP request
 * before we can forward the packet. This packet is added to the ARP request
 * queue as well, so it can be forwarded if/when the ARP reply is received.
 *
 *---------------------------------------------------------------------*/

void create_arp_request(struct sr_instance* sr,
        uint32_t target_ip,
        uint8_t * packet,
        unsigned int len,
        char* iface)
{
    assert(sr);
    assert(iface);

    /* Find interface */
    struct sr_if * if_walker = sr->if_list;
    while(if_walker){
        if( strcmp(if_walker->name, iface) == 0 )
            break;
        if_walker = if_walker->next;
    }

    unsigned int arp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * buf = calloc(1, len);

    char broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* Ethernet */
    sr_ethernet_hdr_t * ether = calloc(1, sizeof(sr_ethernet_hdr_t));
    memcpy(ether->ether_dhost, &broadcast_addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ether->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ether->ether_type = htons(ethertype_arp);

    /* ARP */
    sr_arp_hdr_t * arp_req = calloc(1, sizeof(sr_arp_hdr_t));
    arp_req->ar_hrd = htons(arp_hrd_ethernet);
    arp_req->ar_pro = htons(ethertype_ip);
    arp_req->ar_hln = ETHER_ADDR_LEN;
    arp_req->ar_pln = IP_PROC_LEN;
    arp_req->ar_op = htons(arp_op_request);
    memcpy(arp_req->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
    arp_req->ar_sip = if_walker->ip;
    memcpy(arp_req->ar_tha, &broadcast_addr, ETHER_ADDR_LEN);
    arp_req->ar_tip = target_ip;

    /* Copy into buffer */
    memcpy(buf, ether, sizeof(sr_ethernet_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_req, sizeof(sr_arp_hdr_t));

    /* Add to ARP Request Queue */
    struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, target_ip, buf, arp_len, iface);
    if (req->times_sent == 0){
        time_t now;
        time(&now);
        sr_send_packet(sr, buf, arp_len, iface);
        req->sent = now;
        req->times_sent++;
    }
    sr_arpcache_queuereq(&sr->cache, target_ip, packet, len, iface);
}

/*---------------------------------------------------------------------
 * Method: create_arp_reply(sr_ethernet_hdr_t *ether_packet,
                            sr_arp_hdr_t *arp_req,
                            struct sr_if *if_walker)
 * Scope:  Local
 *
 * This method is called when the router receives an arp request and it has
 * to send a reply back to the host who sent the ARP. This method creates a
 * packet buffer and creates packets in the order: Ethernet, ARP.
 *
 *---------------------------------------------------------------------*/

void create_arp_reply(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_arp_hdr_t *arp_req,
        struct sr_if *if_walker)
{
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * buf = calloc(1, len);

    /* Ethernet */
    sr_ethernet_hdr_t * ether = calloc(1, sizeof(sr_ethernet_hdr_t));
    memcpy(ether->ether_dhost, ether_packet->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ether->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ether->ether_type = htons(ethertype_arp);

    /* ARP */
    sr_arp_hdr_t * arp_reply = calloc(1, sizeof(sr_arp_hdr_t));
    arp_reply->ar_hrd = htons(arp_hrd_ethernet);
    arp_reply->ar_pro = htons(ethertype_ip);
    arp_reply->ar_hln = ETHER_ADDR_LEN;
    arp_reply->ar_pln = IP_PROC_LEN;
    arp_reply->ar_op = htons(arp_op_reply);
    memcpy(arp_reply->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
    arp_reply->ar_sip = if_walker->ip;
    memcpy(arp_reply->ar_tha, arp_req->ar_sha, ETHER_ADDR_LEN);
    arp_reply->ar_tip = arp_req->ar_sip;

    /* Copy into buffer */
    memcpy(buf, ether, sizeof(sr_ethernet_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_reply, sizeof(sr_arp_hdr_t));

    const char * if_name = (const char*) if_walker->name;
    sr_send_packet(sr, buf, len, if_name);
}

/*---------------------------------------------------------------------
 * Method: send_icmp_port_unreachable(sr_ethernet_hdr_t *ether_packet,
                                      sr_ip_hdr_t *ip_packet,
                                      char *iface)
 * Scope:  Local
 *
 * This method is called when the router receives a TCP/UDP packet on one of
 * its router interfaces. In that case, the router needs to reply with an
 * icmp_port_unreachable as it doesn't service TCP/UDP ports. Hence, the method
 * creates a packet buffer and creates packets in the order: Ethernet, IP, ICMP
 * and sends it back to the source address of the original incoming packet.
 *
 *---------------------------------------------------------------------*/

void send_icmp_port_unreachable(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_ip_hdr_t *ip_packet,
        char* iface)
{
    /* Find interface */
    struct sr_if * if_walker = sr->if_list;
    while(if_walker){
        if(strcmp(if_walker->name, iface) == 0)
            break;
        if_walker = if_walker->next;
    }

    /* Create buffer */
    uint8_t icmp_buflen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t * icmp_buf = calloc(1, icmp_buflen);

    /* Ethernet */
    sr_ethernet_hdr_t * ether = calloc(1, sizeof(sr_ethernet_hdr_t));
    memcpy(ether->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ether->ether_dhost, ether_packet->ether_shost, ETHER_ADDR_LEN);
    ether->ether_type = htons(ethertype_ip);

    /* IP */
    sr_ip_hdr_t * ip_packet_new = calloc(1, sizeof(sr_ip_hdr_t));
    memcpy(ip_packet_new, ip_packet, sizeof(sr_ip_hdr_t));
    ip_packet_new->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    ip_packet_new->ip_id = 0;
    ip_packet_new->ip_ttl = 100;
    ip_packet_new->ip_p = ip_protocol_icmp;
    ip_packet_new->ip_sum = 0;
    ip_packet_new->ip_dst = ip_packet->ip_src;
    ip_packet_new->ip_src = ip_packet->ip_dst;
    ip_packet_new->ip_sum = cksum(ip_packet_new, sizeof(sr_ip_hdr_t));

    /* ICMP */
    sr_icmp_t11_hdr_t * icmp_packet = calloc(1, sizeof(sr_icmp_t11_hdr_t));
    icmp_packet->icmp_type = icmp_dest_unreachable;
    icmp_packet->icmp_code = icmp_port_unreachable;
    icmp_packet->icmp_sum = 0;
    memcpy(icmp_packet->data, ip_packet, ICMP_DATA_SIZE);
    icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t11_hdr_t));

    /* Copy in buffer */
    memcpy(icmp_buf, ether, sizeof(sr_ethernet_hdr_t));
    memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t), ip_packet_new, sizeof(sr_ip_hdr_t));
    memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_packet, sizeof(sr_icmp_t11_hdr_t));

    sr_send_packet(sr, icmp_buf, icmp_buflen, iface);
}

/*---------------------------------------------------------------------
 * Method: send_icmp_ttl_exceeded(sr_ethernet_hdr_t *ether_packet,
                                  sr_ip_hdr_t *ip_packet,
                                  char *iface)
 * Scope:  Local
 *
 * This method is called when the ttl on an ip packet is decremeted to
 * 0. This method sends an icmp ttl exceeded packet back to the host who sent
 * the packet to the router. The method creates a packet buffer and creates
 * packets in the order: Ethernet, IP, ICMP
 *
 *---------------------------------------------------------------------*/

void send_icmp_ttl_exceeded(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_ip_hdr_t *ip_packet,
        char* iface)
{
    /* Find interface */
    struct sr_if * if_walker = sr->if_list;
    while(if_walker){
        if(strcmp(if_walker->name, iface) == 0)
            break;
        if_walker = if_walker->next;
    }

    /* Create buffer */
    uint8_t icmp_buflen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t * icmp_buf = calloc(1, icmp_buflen);

    /* Ethernet */
    sr_ethernet_hdr_t * ether = calloc(1, sizeof(sr_ethernet_hdr_t));
    memcpy(ether->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ether->ether_dhost, ether_packet->ether_shost, ETHER_ADDR_LEN);
    ether->ether_type = htons(ethertype_ip);

    /* IP */
    sr_ip_hdr_t * ip_packet_new = calloc(1, sizeof(sr_ip_hdr_t));
    memcpy(ip_packet_new, ip_packet, sizeof(sr_ip_hdr_t));
    ip_packet_new->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    ip_packet_new->ip_id = 0;
    ip_packet_new->ip_ttl = 100;
    ip_packet_new->ip_p = ip_protocol_icmp;
    ip_packet_new->ip_sum = 0;
    ip_packet_new->ip_dst = ip_packet->ip_src;
    ip_packet_new->ip_src = if_walker->ip;
    ip_packet_new->ip_sum = cksum(ip_packet_new, sizeof(sr_ip_hdr_t));

    /* ICMP */
    sr_icmp_t11_hdr_t * icmp_packet = calloc(1, sizeof(sr_icmp_t11_hdr_t));
    icmp_packet->icmp_type = icmp_ttl_expired;
    icmp_packet->icmp_sum = 0;
    memcpy(icmp_packet->data, ip_packet, ICMP_DATA_SIZE);
    icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t11_hdr_t));

    /* Copy in buffer */
    memcpy(icmp_buf, ether, sizeof(sr_ethernet_hdr_t));
    memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t), ip_packet_new, sizeof(sr_ip_hdr_t));
    memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_packet, sizeof(sr_icmp_t11_hdr_t));

    sr_send_packet(sr, icmp_buf, icmp_buflen, iface);
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* iface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * iface.  The packet buffer, the packet length and the receiving
 * iface are passed in as parameters. The packet is complete with
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
        char* iface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    fprintf(stderr, "*** -> Received packet of length %d \n",len);

    /* Check Packet Length */
    if (len < sizeof(sr_ethernet_hdr_t))
        return;

    sr_ethernet_hdr_t * ether_packet = (sr_ethernet_hdr_t*) packet;

    /* IP Packet */
    if (ethertype(packet) == ethertype_ip){
        if(len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)))
            return;

        uint8_t * ip_packet_raw = packet + sizeof(sr_ethernet_hdr_t);
        uint8_t * icmp_packet_raw = ip_packet_raw + sizeof(sr_ip_hdr_t);

        sr_ip_hdr_t * ip_packet = (sr_ip_hdr_t*)ip_packet_raw;
        /* Checksum */
        uint16_t packet_sum = ip_packet->ip_sum;
        ip_packet->ip_sum = 0;
        uint16_t checksum = cksum(ip_packet, sizeof(sr_ip_hdr_t));
        if(checksum != packet_sum){
            fprintf(stderr, "Checksum Invalid\n");
            return;
        }

        struct sr_if * if_walker = (struct sr_if*)(sr->if_list);
        uint8_t * ret_addr = calloc(1, sizeof(uint8_t) * ETHER_ADDR_LEN);

        /* Check if packet is for router */
        int packet_for_me = 0;

        while(if_walker){
            /* Find address of interface to send reply from */
            if(strcmp(if_walker->name, iface) == 0)
                memcpy(ret_addr, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

            /* If packet is for router's interfaces */
            if(if_walker->ip == ip_packet->ip_dst){
                packet_for_me = 1;

                /* Packet type is ICMP */
                if(ip_protocol(ip_packet_raw) == ip_protocol_icmp){
                    /* Ethernet */
                    memcpy(ether_packet->ether_dhost, ether_packet->ether_shost, ETHER_ADDR_LEN);
                    memcpy(ether_packet->ether_shost, ret_addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

                    /* IP */
                    ip_packet->ip_ttl = 100;
                    ip_packet->ip_dst = ip_packet->ip_src;
                    ip_packet->ip_src = if_walker->ip;
                    ip_packet->ip_sum = 0;
                    ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

                    /* ICMP */
                    sr_icmp_t11_hdr_t * icmp_packet = (sr_icmp_t11_hdr_t*)(ip_packet_raw+sizeof(sr_ip_hdr_t));
                    icmp_packet->icmp_type = icmp_echo_reply;
                    icmp_packet->icmp_sum = 0;
                    icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t11_hdr_t));
                    sr_send_packet(sr, packet, len, iface);
                }
                /* Packet type is TCP/UDP */
                else{
                    send_icmp_port_unreachable(sr, ether_packet, ip_packet, iface);
                }
            }
            if_walker = if_walker->next;
        }
        /* Packet NOT for router */
        if (!packet_for_me){
            ip_packet->ip_ttl -= 1;

            /* Check if TTL exceeded */
            if(ip_packet->ip_ttl == 0) {
                fprintf(stderr, "TTL Exceeded\n");
                send_icmp_ttl_exceeded(sr, ether_packet, ip_packet, iface);
                return;
            }

            /* Find dest host in routing table to forward packet */
            struct sr_rt * rt_walker = long_pref_match(sr, ip_packet->ip_dst);

            if(rt_walker){
                /* If dest host is found in routing table */
                ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

                /* Looking IP in arp cache to check if we have a stored IP-MAC mapping */
                struct sr_arpentry *cache = sr_arpcache_lookup(&sr->cache, ip_packet->ip_dst);

                /* If cache hits */
                if(cache){
                    /* Find interface addr to send on */
                    fprintf(stderr, "Cache hit\n");
                    struct sr_if * if_walker = sr->if_list;
                    while(if_walker){
                        if( strcmp(if_walker->name, rt_walker->interface) == 0 ){
                            break;
                        }
                        if_walker = if_walker->next;
                    }

                    memcpy(ether_packet->ether_dhost, cache->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
                    memcpy(ether_packet->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
                    sr_send_packet(sr, packet, len, rt_walker->interface);
                }
                /* If cache misses, send ARP request */
                else {
                    memset(ether_packet->ether_dhost, 0, ETHER_ADDR_LEN);

                    fprintf(stderr, "Cache miss\n");
                    create_arp_request(sr, ip_packet->ip_dst, packet, len, rt_walker->interface);
                }

            }
            /* Host not in routing table, send net icmp_net_unreachabe */
            else{
                /* Find interface */
                if_walker = sr->if_list;
                while(if_walker){
                    if(strcmp(if_walker->name, iface) == 0){
                        break;
                    }
                    if_walker = if_walker->next;
                }

                /* Create buffer */
                uint8_t icmp_buflen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
                uint8_t * icmp_buf = calloc(1, icmp_buflen);

                /* Ethernet */
                sr_ethernet_hdr_t * ether = calloc(1, sizeof(sr_ethernet_hdr_t));
                memcpy(ether->ether_shost, ether_packet->ether_dhost, ETHER_ADDR_LEN);
                memcpy(ether->ether_dhost, ether_packet->ether_shost, ETHER_ADDR_LEN);
                ether->ether_type = htons(ethertype_ip);

                /* IP */
                sr_ip_hdr_t * ip_packet_new = calloc(1, sizeof(sr_ip_hdr_t));
                memcpy(ip_packet_new, ip_packet, sizeof(sr_ip_hdr_t));
                ip_packet_new->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
                ip_packet_new->ip_id = 0;
                ip_packet_new->ip_ttl = 100;
                ip_packet_new->ip_p = ip_protocol_icmp;
                ip_packet_new->ip_sum = 0;
                ip_packet_new->ip_dst = ip_packet->ip_src;
                ip_packet_new->ip_src = if_walker->ip;
                ip_packet_new->ip_sum = cksum(ip_packet_new, sizeof(sr_ip_hdr_t));

                /* ICMP */
                sr_icmp_t11_hdr_t * icmp_packet = calloc(1, sizeof(sr_icmp_t11_hdr_t));
                memcpy(icmp_packet, ip_packet+sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t11_hdr_t));
                icmp_packet->icmp_type = icmp_dest_unreachable;
                icmp_packet->icmp_code = icmp_net_unreachable;
                icmp_packet->unused = 0;
                icmp_packet->icmp_sum = 0;
                memcpy(icmp_packet->data, ip_packet_raw, sizeof(sr_ip_hdr_t));
                memcpy(icmp_packet->data+sizeof(sr_ip_hdr_t), icmp_packet_raw, 8);
                icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t11_hdr_t));

                /* Copy into buffer */
                memcpy(icmp_buf, ether, sizeof(sr_ethernet_hdr_t));
                memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t), ip_packet_new, sizeof(sr_ip_hdr_t));
                memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_packet, sizeof(sr_icmp_t11_hdr_t));

                sr_send_packet(sr, icmp_buf, icmp_buflen, iface);
            }
        }
    }
    /* ARP Packet */
    else if(ethertype(packet) == ethertype_arp){
        /* Check size */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
            return;

        fprintf(stderr, "ARP\n");
        uint8_t * arp_packet = packet + sizeof(sr_ethernet_hdr_t);
        sr_arp_hdr_t * arp_req = (sr_arp_hdr_t *)arp_packet;

        struct sr_if * if_walker = (struct sr_if*)(sr->if_list);
        while(if_walker){
            /* Sender wants to resolve router's MAC address */
            if (if_walker->ip == arp_req->ar_tip){
                /* ARP reply received */
                if(ntohs(arp_req->ar_op) == arp_op_reply){
                    fprintf(stderr, "ARP Reply\n");
                    /* Load ARP request and insert IP-MAC mapping into cache */
                    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, &arp_req->ar_sha[0], arp_req->ar_sip);
                    /* If outstanding packets found */
                    if(req){
                        struct sr_packet * packet = req->packets;
                        /* Forward all IP packets waiting on ARP */
                        while(packet){
                            if(ethertype(packet->buf) == ethertype_ip){
                                sr_ethernet_hdr_t * ether_packet = (sr_ethernet_hdr_t*)packet->buf;
                                memcpy(ether_packet->ether_dhost, arp_req->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
                                memcpy(ether_packet->ether_shost, if_walker->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
                                sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                                sr_arpreq_destroy(&sr->cache, req);
                            }
                            packet = packet->next;
                        }
                    }
                }
                /* ARP request received */
                else if( ntohs(arp_req->ar_op) == arp_op_request ) {
                    /* Insert IP-MAC mapping from request into cache */
                    sr_arpcache_insert(&sr->cache, &ether_packet->ether_shost[0], arp_req->ar_sip);
                    create_arp_reply(sr, ether_packet, arp_req, if_walker);
                    break;
                }
            }
            if_walker = if_walker->next;
        }
    }
}/* end sr_handlepacket */
