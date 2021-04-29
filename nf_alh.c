#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jikui Pei");
MODULE_DESCRIPTION("Auto Last Hop");
static char * ip_mark = "10.145.71.34";
static unsigned short src_port = 80;
static u8 src_mac[ETH_ALEN] = {0};
static struct net_device *in_dev = NULL;

static unsigned int
nf_alh_in_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*));

static unsigned int
nf_alh_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*));

static struct nf_hook_ops nf_alh_ops[] __read_mostly = {
  {
    .hook = nf_alh_in_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
  },
  {
    .hook = nf_alh_out_hook,
    .pf = NFPROTO_IPV4,
    //.hooknum = NF_INET_POST_ROUTING,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
  },
};
void hdr_dump(struct ethhdr *ehdr) {
    printk("[MAC_DES:%x,%x,%x,%x,%x,%x" 
           "MAC_SRC: %x,%x,%x,%x,%x,%x Prot:%x]\n",
           ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],
           ehdr->h_dest[4],ehdr->h_dest[5],ehdr->h_source[0],ehdr->h_source[1],
           ehdr->h_source[2],ehdr->h_source[3],ehdr->h_source[4],
           ehdr->h_source[5],ehdr->h_proto);
}
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

static unsigned int
nf_alh_in_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*)) {
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;
  eth_header = (struct ethhdr *)(skb_mac_header(skb));
  ip_header = (struct iphdr *)(skb_network_header(skb));
  if (ip_header->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }
  
  tcp_header = (struct tcphdr*)((unsigned char *)ip_header  + (ip_header->ihl << 2));
  if (ip_header->daddr == in_aton(ip_mark) &&  ntohs(tcp_header->dest) == src_port) {
      /*record the incoming netif and the source mac.*/
      in_dev = skb->dev;
      memcpy(src_mac,eth_header->h_source, ETH_ALEN); 
      printk("from Local In\n");
      printk("src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' , dst port: %u\n",
              NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr), src_port);
      hdr_dump(eth_header);
      printk("from Local In over\n");
  }
  return NF_ACCEPT;
}

static unsigned int
nf_alh_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*)) {
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;
  struct net_device * dev;
  int ret = 0;

  eth_header = (struct ethhdr *)(skb_mac_header(skb));
  ip_header = (struct iphdr *)(skb_network_header(skb));
  if (ip_header->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }
  tcp_header = (struct tcphdr*)((unsigned char *)ip_header  + (ip_header->ihl << 2));

  if (ip_header->saddr == in_aton(ip_mark) &&  ntohs(tcp_header->source) == src_port) {
      printk("jikui from Post Routing.\n");
      printk("src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' , src port: %u\n",
              NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr), src_port);
      eth_header = (struct ethhdr *)skb_push(skb,ETH_HLEN);
      /*replace the dest mac with the source mac address recorded.*/
      memcpy(eth_header->h_dest,src_mac,ETH_ALEN);
      eth_header->h_proto = htons(ETH_P_IP);
      hdr_dump(eth_header);
      /*replace the out if with the in if recorded.*/
      skb->dev = in_dev;
      
      ret = dev_queue_xmit(skb);
      if (ret < 0) {
        printk("sending packet error.\n");
        dev_put(dev);
      }
      return NF_STOLEN;
    }
  return NF_ACCEPT;
}

static int __init init_nf_alh(void) {
  int ret;
  ret = nf_register_hooks(nf_alh_ops, ARRAY_SIZE(nf_alh_ops));
  if (ret < 0) {
    printk("register nf hook fail\n");
    return ret;
  }
  printk(KERN_NOTICE "register nf alh hook\n");
  return 0;
}

static void __exit exit_nf_alh(void) {
  nf_unregister_hooks(nf_alh_ops, ARRAY_SIZE(nf_alh_ops));
}

module_init(init_nf_alh);
module_exit(exit_nf_alh);
