#ifndef __PPP_H__
#define __PPP_H__
#include <linux/if_pppox.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/ppp-comp.h>
struct ppp_file {
    enum {
        INTERFACE=1, CHANNEL
    }       kind;
    struct sk_buff_head xq;     /* pppd transmit queue */
    struct sk_buff_head rq;     /* receive queue for pppd */
    wait_queue_head_t rwait;    /* for poll on reading /dev/ppp */
    refcount_t  refcnt;     /* # refs (incl /dev/ppp attached) */
    int     hdrlen;     /* space to leave for headers */
    int     index;      /* interface unit / channel number */
    int     dead;       /* unit/channel has been shut down */
};

struct channel {
    struct ppp_file file;       /* stuff for read/write/poll */
    struct list_head list;      /* link in all/new_channels list */
    struct ppp_channel *chan;   /* public channel data structure */
    struct rw_semaphore chan_sem;   /* protects `chan' during chan ioctl */
    spinlock_t  downl;      /* protects `chan', file.xq dequeue */
    void  *ppp;
    struct net  *chan_net;  /* the net channel belongs to */
    struct list_head clist;     /* link in list of channels per unit */
    rwlock_t    upl;        /* protects `ppp' */
#ifdef CONFIG_PPP_MULTILINK
    u8      avail;      /* flag used in multilink stuff */
    u8      had_frag;   /* >= 1 fragments have been sent */
    u32     lastseq;    /* MP: last sequence # received */
    int     speed;      /* speed of the corresponding ppp channel*/
#endif /* CONFIG_PPP_MULTILINK */
};

struct ppp_link_stats {
    u64 rx_packets;
    u64 tx_packets;
    u64 rx_bytes;
    u64 tx_bytes;
};

#define NUM_NP  6
struct ppp {
    struct ppp_file file;       /* stuff for read/write/poll 0 */
    struct file *owner;     /* file that owns this unit 48 */
    struct list_head channels;  /* list of attached channels 4c */
    int     n_channels; /* how many channels are attached 54 */
    spinlock_t  rlock;      /* lock for receive side 58 */
    spinlock_t  wlock;      /* lock for transmit side 5c */
    int __percpu    *xmit_recursion; /* xmit recursion detect */
    int     mru;        /* max receive unit 60 */
    unsigned int    flags;      /* control bits 64 */
    unsigned int    xstate;     /* transmit state bits 68 */
    unsigned int    rstate;     /* receive state bits 6c */
    int     debug;      /* debug flags 70 */
    struct slcompress *vj;      /* state for VJ header compression */
    enum NPmode npmode[NUM_NP]; /* what to do with each net proto 78 */
    struct sk_buff  *xmit_pending;  /* a packet ready to go out 88 */
    struct compressor *xcomp;   /* transmit packet compressor 8c */
    void        *xc_state;  /* its internal state 90 */
    struct compressor *rcomp;   /* receive decompressor 94 */
    void        *rc_state;  /* its internal state 98 */
    unsigned long   last_xmit;  /* jiffies when last pkt sent 9c */
    unsigned long   last_recv;  /* jiffies when last pkt rcvd a0 */
    struct net_device *dev;     /* network interface device a4 */
    int     closing;    /* is device closing down? a8 */
#ifdef CONFIG_PPP_MULTILINK
    int     nxchan;     /* next channel to send something on */
    u32     nxseq;      /* next sequence number to send */
    int     mrru;       /* MP: max reconst. receive unit */
    u32     nextseq;    /* MP: seq no of next packet */
    u32     minseq;     /* MP: min of most recent seqnos */
    struct sk_buff_head mrq;    /* MP: receive reconstruction queue */
#endif /* CONFIG_PPP_MULTILINK */
#ifdef CONFIG_PPP_FILTER
    struct bpf_prog *pass_filter;   /* filter for packets to pass */
    struct bpf_prog *active_filter; /* filter for pkts to reset idle */
#endif /* CONFIG_PPP_FILTER */
    struct net  *ppp_net;   /* the net we belong to */
    struct ppp_link_stats stats64;  /* 64 bit network stats */
};

#endif
