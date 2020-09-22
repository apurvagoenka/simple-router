#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"


/*---------------------------------------------------------------------
 * Method: send_icmp_host_unreachable(sr_arpreq * req_walker)

 * Scope:  Local
 *
 * This method is called when a timeout occurs after a host hasn't responded
 * to the router's ARP request. This method sends an icmp_host_unreachable
 * packet back to the sender of the packets that are waiting on the ARP reply.
 * This method loads all the pending packets, then for each packet, creates
 * the icmp packet and sends it.
 *
 * This method creates a packet buffer then creates and copies packets in the
 * order: Ethernet, IP, ICMP.
 *
 *---------------------------------------------------------------------*/

void send_icmp_host_unreachable(struct sr_instance *sr,
        struct sr_arpreq * req_walker)
{
    /* Load all packets waiting on ARP reply */
    struct sr_packet * packet = req_walker->packets;
    while(packet){
        if(ethertype(packet->buf) == ethertype_ip){
            /* Type define buffer and get different packets */
            sr_ethernet_hdr_t * ether_packet = (sr_ethernet_hdr_t*)(packet->buf);
            sr_ip_hdr_t * ip_packet = (sr_ip_hdr_t*)(packet->buf+(sizeof(sr_ethernet_hdr_t)));
            sr_icmp_t11_hdr_t * icmp_packet_old = (sr_icmp_t11_hdr_t*)(packet->buf+(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)));

            /* find interface where source IP address lies */
            struct sr_rt * rt_walker = sr->routing_table;
            while(rt_walker){
                if(rt_walker->dest.s_addr == ip_packet->ip_src){
                    break;
                }
                rt_walker = rt_walker->next;
            }
            struct sr_if * if_walker = sr->if_list;
            while(if_walker){
                if( strcmp(if_walker->name, rt_walker->interface) == 0){
                    break;
                }
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
            memcpy(icmp_packet, ip_packet+sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t11_hdr_t));
            icmp_packet->icmp_type = icmp_dest_unreachable;
            icmp_packet->icmp_code = icmp_host_unreachable;
            icmp_packet->unused = 0;
            icmp_packet->icmp_sum = 0;
            memcpy(icmp_packet->data, ip_packet, sizeof(sr_ip_hdr_t));
            memcpy(icmp_packet->data+sizeof(sr_ip_hdr_t), icmp_packet_old, 8);
            icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t11_hdr_t));

            /* Copy into buffer */
            memcpy(icmp_buf, ether, sizeof(sr_ethernet_hdr_t));
            memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t), ip_packet_new, sizeof(sr_ip_hdr_t));
            memcpy(icmp_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_packet, sizeof(sr_icmp_t11_hdr_t));

            sr_send_packet(sr, icmp_buf, icmp_buflen, if_walker->name);
            break;
        }
        packet = packet->next;
    }
    sr_arpreq_destroy(&sr->cache, req_walker);
}

/*---------------------------------------------------------------------
 * Method: sr_arpcache_sweepreqs()

 * Scope:  Global
 *
 * This method gets called every second. For every ARP request we send out,
 * we want to check if a reply was received, and if not, we want to resend
 * the ARP.
 *
 *---------------------------------------------------------------------*/

void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Load all ARP requests */
    struct sr_arpreq * req_walker = sr->cache.requests;
    while(req_walker){
        /* get current time */
        time_t now;
        time(&now);
        /* Load request */
        struct sr_arpreq * next_req = req_walker->next;
        /* Check if a second has passed since we sent the ARP */
        if (difftime(now, req_walker->sent) >= 1.0){
            /* Send ICMP host unreachable */
            if (req_walker->times_sent >= 5){
                fprintf(stderr, "Send ICMP host unreachable\n");
                send_icmp_host_unreachable(sr, req_walker);
            }
            else {
                fprintf(stderr, "Send ARP\n");
                /* Load all packets in cache */
                struct sr_packet * packet = req_walker->packets;
                while(packet){
                    if(ethertype(packet->buf) == ethertype_arp){
                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                        break;
                    }
                    packet = packet->next;
                }
                /* save new timestamp */
                time(&now);
                req_walker->sent = now;
                req_walker->times_sent++;
            }
        }
        req_walker = next_req;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
