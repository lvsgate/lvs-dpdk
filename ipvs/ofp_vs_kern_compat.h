#ifndef __OFP_VS_KERN_COMPAT_H__
#define __OFP_VS_KERN_COMPAT_H__

#include "rte_config.h"
#include "rte_atomic.h"
#include "rte_rwlock.h"
#include "rte_spinlock.h"

#define IP_VS_POSSIBLE_CPU 32

#define DECLARE_PER_CPU(__type, __varname) \
	extern __type __varname##_array[IP_VS_POSSIBLE_CPU]

#define DEFINE_PER_CPU(__type, __varname) \
	__type __varname##_array[IP_VS_POSSIBLE_CPU]

#define per_cpu(__varname, __cpu) \
	__varname##_array[__cpu]

#define __get_cpu_var(__varname) \
	__varname##_array[rte_lcore_id()]

#define cpu_to_node(__cpu) \
	rte_lcore_to_socket_id(__cpu)

#define for_each_possible_cpu(__cpu) \
	for (__cpu = 0; __cpu <	IP_VS_POSSIBLE_CPU; __cpu++)

#define num_possible_cpus() IP_VS_POSSIBLE_CPU

#define for_each_online_cpu(__cpu) \
	RTE_LCORE_FOREACH(__cpu)

#define smp_processor_id() rte_lcore_id() 


typedef rte_spinlock_t spinlock_t; 

#define spinlock_init(__lock) \
	rte_spinlock_init(__lock)

#define spin_lock(__lock) \
	rte_spinlock_lock(__lock)

#define spin_unlock(__lock) \
	rte_spinlock_unlock(__lock)

#define spin_lock_bh spin_lock
#define spin_unlock_bh spin_unlock

#define spin_lock_init rte_spinlock_init

#define rwlock_init(__lock) \
	rte_rwlock_init(__lock)

#define read_lock(__lock) \
	rte_rwlock_read_lock(__lock)

#define read_unlock(__lock) \
	rte_rwlock_read_unlock(__lock)

#define write_lock(__lock) \
	rte_rwlock_write_lock(__lock)

#define write_unlock(__lock) \
	rte_rwlock_write_unlock(__lock)

#define write_lock_bh write_lock
#define write_unlock_bh write_unlock

typedef rte_rwlock_t rwlock_t;

#define ATOMIC_INIT(__var) RTE_ATOMIC32_INIT(__var)
typedef rte_atomic32_t atomic_t;
#define atomic_inc(__var) rte_atomic32_inc(__var)
#define atomic_dec(__var) rte_atomic32_dec(__var)
#define atomic_set(__dst, __var) rte_atomic32_set(__dst, __var)
#define atomic_read(__var) rte_atomic32_read(__var)
#define atomic_dec_and_test(__var) rte_atomic32_dec_and_test(__var)

typedef rte_atomic64_t atomic64_t;
#define atomic64_inc(__var) rte_atomic64_inc(__var)
#define atomic64_dec(__var) rte_atomic64_dec(__var)
#define atomic64_set(__var) rte_atomic64_set(__var)
#define atomic64_read(__var) rte_atomic64_read(__var)
#define atomic64_dec_and_test(__var) rte_atomic64_dec_and_test(__var)
#define atomic64_inc_return(__var) rte_atomic64_add_return(__var)

#define rcu_read_lock() nf_rcu_read_lock
#define rcu_read_unlock() nf_rcu_read_unlock



#define PRINT_IP_FORMAT "%u.%u.%u.%u"
#define  PRINT_NIP(x)\
	((x >>  0) & 0xFF),\
	((x >>  8) & 0xFF),\
	((x >> 16) & 0xFF),\
	((x >> 24) & 0xFF)


#ifdef CONFIG_IP_VS_DEBUG

extern int ip_vs_get_debug_level(void);

static inline const char *ip_vs_dbg_addr(int af, char *buf, size_t buf_len,
					 const union nf_inet_addr *addr,
					 int *idx)
{
	int len;
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		len = snprintf(&buf[*idx], buf_len - *idx, "[%pI6]",
			       &addr->in6) + 1;
	else
#endif
		len = snprintf(&buf[*idx], buf_len - *idx, PRINT_IP_FORMAT,
			       PRINT_NIP(addr->ip)) + 1;

	*idx += len;
	RTE_BUILD_BUG_ON(*idx > buf_len + 1);
	return &buf[*idx - len];
}

#define IP_VS_DBG(__level, __fmt, args...) \
	NF_LOG(DEBUG, __fmt, ##args)


#define IP_VS_DBG_BUF(__level, __fmt, args...) 			\
	do { 							\
		char ip_vs_dbg_buf[160];			\
		int ip_vs_dbg_idx = 0;				\
		if (ip_vs_get_debug_level() >= NF_LOG_DEBUG)	\
			NF_LOG(DEBUG, __fmt, ##args);		\
	} while (0)

#define IP_VS_ERR_BUF(__fmt, args...)				\
	do { 							\
		char ip_vs_dbg_buf[160];			\
		int ip_vs_dbg_idx = 0;				\
		if (ip_vs_get_debug_level() >= NF_LOG_DEBUG)	\
			NF_LOG(ERROR, __fmt, ##args);		\
	} while (0)

#define IP_VS_DBG_ADDR(af, addr)					\
	ip_vs_dbg_addr(af, ip_vs_dbg_buf,				\
		       sizeof(ip_vs_dbg_buf), addr,			\
		       &ip_vs_dbg_idx)


#define IP_VS_DBG_PKT(level, pp, skb, ofs, msg)			\
	do {							\
		if (ip_vs_get_debug_level() >= NF_LOG_DEBUG)	\
			pp->debug_packet(pp, skb, ofs, msg);	\
	} while (0)


#define IP_VS_DBG_RL(msg...)  do {} while (0)
#define IP_VS_DBG_RL_PKT(level, pp, skb, ofs, msg)	do {} while (0)

#define EnterFunction(__level) \
	NF_LOG(DEBUG, "Enter\n")

#define LeaveFunction(__level) \
	NF_LOG(DEBUG, "Lever\n")

#else  /* NO DEBUGGING at ALL */

#define IP_VS_DBG_BUF(level, msg...)  do {} while (0)
#define IP_VS_ERR_BUF(msg...)  do {} while (0)
#define IP_VS_DBG(level, msg...)  do {} while (0)
#define IP_VS_DBG_RL(msg...)  do {} while (0)
#define IP_VS_DBG_PKT(level, pp, skb, ofs, msg)		do {} while (0)
#define IP_VS_DBG_RL_PKT(level, pp, skb, ofs, msg)	do {} while (0)
#define EnterFunction(level)   do {} while (0)
#define LeaveFunction(level)   do {} while (0)

#endif /* CONFIG_IP_VS_DEBUG */


#define IP_VS_ERR_RL(__fmt, args...) \
	NF_LOG(ERROR, __fmt, ##args)

#define pr_err(__fmt, args...) \
	NF_LOG(ERROR, __fmt, ##args)

#define pr_info(__fmt, args...) \
	NF_LOG(INFO, __fmt, ##args)

#define ETH_ALEN ETHER_ADDR_LEN

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
*/
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})


#define time_after64(a, b) \
	(typecheck(uint64_t, a) && \
	 typecheck(uint64_t, b) && \
	((int64_t)(b) - (int64_t)(a) < 0))

#define time_before64(a, b) time_after64(b, a)

#define time_after64_eq(a, b) \
	(typecheck(uint64_t, a) && \
	 typecheck(uint64_t, b) && \
	((int64_t)(b) - (int64_t)(a) <= 0))



#define IP_VS_INC_ESTATS(esmib, id)

#define PROT_SOCK 1024

#define jiffies rte_get_timer_cycles()

#endif
