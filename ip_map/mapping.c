#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/netlink.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/vmalloc.h>
#include <linux/inet.h>
#include "ppp.h"
unsigned short magic = 0x48f4;

static unsigned int static_nat(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct in_device *indev;
    struct net_device *dev;
    __be32 new_addr = 0;
    __be32 addr;
    int ihl;
    int noff;
    int hooknum = state->hook;

    if (hooknum == NF_INET_PRE_ROUTING) {
        dev = state->in;
    }else{
        dev = state->out;
    }

    if (dev == NULL) {
        return NF_ACCEPT;
    }

    if (dev->flags & IFF_POINTOPOINT) {
        struct ppp *ppp = (struct ppp *)netdev_priv(dev);
        struct list_head *list = &ppp->channels;
        struct channel *ch = list_entry(list->next, struct channel, clist);
        struct ppp_channel *chan = ch->chan;
        if (chan->ops->ioctl == NULL) {
            // it is pppoe channel, ppp-async has ioctl interface, pppoe doesn't
            // ugly, but doesn't has anthor method to do this.
            struct sock *sk = (struct sock *)chan->private;
            struct pppox_sock *po = pppox_sk(sk);
            dev = po->pppoe_dev;
        } else {
            return NF_ACCEPT;
        }
    }

    if (magic != (dev->dev_addr[0] << 8 | dev->dev_addr[1])) {
        return NF_ACCEPT;
    }

    noff = skb_network_offset(skb);
    if (!pskb_may_pull(skb, sizeof(*iph) + noff)) {
        goto drop;
    }

    iph = ip_hdr(skb);

    if (hooknum == NF_INET_PRE_ROUTING) {
        addr = iph->daddr;
        new_addr = cpu_to_be32(dev->dev_addr[2] << 24| dev->dev_addr[3] << 16
                | dev->dev_addr[4] << 8 | dev->dev_addr[5]);
    } else {
        addr = iph->saddr;
        indev = in_dev_get(state->out);
        for_primary_ifa(indev) {
            new_addr = ifa->ifa_local;
        }endfor_ifa(in_dev);
        in_dev_put(indev);
    }

    if (new_addr == 0) {
        goto drop;
    }

    if (skb_try_make_writable(skb, sizeof(*iph) + noff)) {
        goto drop;
    }

    iph = ip_hdr(skb);
    // at end will rewrite ip header, because we will bypass ssh
    ihl = iph->ihl * 4;


    switch (iph->frag_off & htons(IP_OFFSET) ? 0 : iph->protocol) {
        case IPPROTO_TCP:
            {
                struct tcphdr *tcph;

                if (!pskb_may_pull(skb, ihl + sizeof(*tcph) + noff) ||
                        skb_try_make_writable(skb, ihl + sizeof(*tcph) + noff))
                    goto drop;

                tcph = (void *)(skb_network_header(skb) + ihl);
                if (tcph->source == cpu_to_be16(22) || tcph->dest == cpu_to_be16(22))
                    goto drop;
                inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr,
                        true);
                break;
            }
        case IPPROTO_UDP:
            {
                struct udphdr *udph;

                if (!pskb_may_pull(skb, ihl + sizeof(*udph) + noff) ||
                        skb_try_make_writable(skb, ihl + sizeof(*udph) + noff))
                    goto drop;

                udph = (void *)(skb_network_header(skb) + ihl);
                if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
                    inet_proto_csum_replace4(&udph->check, skb, addr,
                            new_addr, true);
                    if (!udph->check)
                        udph->check = CSUM_MANGLED_0;
                }
                break;
            }
        case IPPROTO_ICMP:
            {
                struct icmphdr *icmph;

                if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + noff))
                    goto drop;

                icmph = (void *)(skb_network_header(skb) + ihl);

                if ((icmph->type != ICMP_DEST_UNREACH) &&
                        (icmph->type != ICMP_TIME_EXCEEDED) &&
                        (icmph->type != ICMP_PARAMETERPROB))
                    break;

                if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + sizeof(*iph) +
                            noff))
                    goto drop;

                icmph = (void *)(skb_network_header(skb) + ihl);
                iph = (void *)(icmph + 1);

                if (skb_try_make_writable(skb, ihl + sizeof(*icmph) +
                            sizeof(*iph) + noff))
                    goto drop;

                icmph = (void *)(skb_network_header(skb) + ihl);
                iph = (void *)(icmph + 1);

                /* XXX Fix up the inner checksums. */
                if (hooknum == NF_INET_PRE_ROUTING)
                    iph->daddr = new_addr;
                else
                    iph->saddr = new_addr;

                inet_proto_csum_replace4(&icmph->checksum, skb, addr, new_addr,
                        false);
                break;
            }
        default:
            goto drop;
    }

    /* Rewrite IP header */
    if (hooknum == NF_INET_PRE_ROUTING)
        iph->daddr = new_addr;
    else
        iph->saddr = new_addr;

    csum_replace4(&iph->check, addr, new_addr);

    nf_ct_set(skb, NULL, IP_CT_UNTRACKED);

drop:
    return NF_ACCEPT;
}

static struct nf_hook_ops dnat = {
    .hook       = static_nat,
    .hooknum    = NF_INET_PRE_ROUTING, 
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,

};

static struct nf_hook_ops snat = {
    .hook       = static_nat,
    .hooknum    = NF_INET_POST_ROUTING, 
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,

};

static int __init init_mapping(void)
{
    nf_register_net_hook(&init_net, &dnat);
    nf_register_net_hook(&init_net, &snat);
    return 0;

}

static void __exit exit_mapping(void)
{
    nf_unregister_net_hooks(&init_net, &dnat, 1);
    nf_unregister_net_hooks(&init_net, &snat, 1);
}

module_init(init_mapping);
module_exit(exit_mapping);
MODULE_LICENSE("GPL");
