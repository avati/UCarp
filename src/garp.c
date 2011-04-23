#include <config.h>
#include "ucarp.h"
#include "garp.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif
#include <net/if_arp.h>
#include <netpacket/packet.h>

int gratuitous_arp(const int dev_desc_fd)
{
    static unsigned char pkt[60];
    int pktlen;
    struct arphdr *arphdr = NULL;
    int rc;
    char sockaddr_ll_bytes[32] = {0, };
    struct sockaddr_ll *sll;
    int slen = 0;

    arphdr = (struct arphdr *) pkt;

    /*
     * - Gratuitous ARPs should use requests for the highest interoperability.
     * - Target MAC and IP should match sender
     * http://www1.ietf.org/mail-archive/web/dhcwg/current/msg03797.html
     * http://en.wikipedia.org/wiki/Address_Resolution_Protocol
     * http://ettercap.sourceforge.net/forum/viewtopic.php?t=2392
     * http://wiki.ethereal.com/Gratuitous_ARP
     */
    arphdr->ar_hrd  = htons (hwtype);
    arphdr->ar_pro  = htons (ETH_P_IP);
    arphdr->ar_hln  = addrlen;
    arphdr->ar_pln  = 4;
    arphdr->ar_op   = htons (ARPOP_REQUEST);

    memcpy(&pkt[8], hwaddr, addrlen);                          /* Sender MAC */
    memcpy(&pkt[8+addrlen], &vaddr.s_addr, (size_t) 4U);       /* Sender IP */
    memcpy(&pkt[12+addrlen], hwaddr, addrlen);                 /* Target MAC */
    memcpy(&pkt[12+(addrlen*2)], &vaddr.s_addr, (size_t) 4U);  /* Target IP */

    pktlen = sizeof (*arphdr) + (2 * 4) + (2 * addrlen);

    sll = (struct sockaddr_ll *)sockaddr_ll_bytes;
    sll->sll_family = PF_PACKET;
    sll->sll_protocol = htons (ETH_P_ARP);
    sll->sll_ifindex = ifindex;
    sll->sll_halen = addrlen;

    memcpy (sll->sll_addr, brdaddr, addrlen);
    slen = (addrlen > 8 ? (sizeof (*sll) - 8 + addrlen) : sizeof (*sll));

    do {
	 rc = sendto (dev_desc_fd, pkt, pktlen, 0, sll, slen);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        logfile(LOG_ERR, _("write() in garp: %s"), strerror(errno));
        return -1;
    }
    
    return 0;
}
