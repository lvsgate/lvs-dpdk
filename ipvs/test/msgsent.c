#include <stdlib.h>
#include <errno.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>

#include "../ip_vs.h"


static int family;
static struct nl_sock *sock;

struct genl_ops ip_vs_genl_ops = {
  .o_id = GENL_ID_GENERATE,
  .o_name = IPVS_GENL_NAME,
};

struct nl_msg *ipvs_nl_message(int cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, flags,
		    cmd, IPVS_GENL_VERSION);

	return msg;
}

int ipvs_nl_send_message(struct nl_msg *msg, nl_recvmsg_msg_cb_t func,
                          void *arg)
{

	int err = EINVAL;

	if (!sock) {
    fprintf(stderr, "nl_socket_alloc failed %s\n", strerror(errno));
		nlmsg_free(msg);
		return -1;
	}


	/* To test connections and set the family */
	if (msg == NULL) {
		nl_socket_free(sock);
		sock = NULL;
		return 0;
	}

	if (nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg) != 0) {
    fprintf(stderr, "%s:%d nl_socket_modify_cb failed %s\n", __FILE__, __LINE__, strerror(errno));
		goto fail_genl;
  }

	if (nl_send_auto_complete(sock, msg) < 0) {
    fprintf(stderr, "%s:%d nl_send_auto_complete failed %s\n", __FILE__, __LINE__, strerror(errno));
		goto fail_genl;
  }

	if ((err = -nl_recvmsgs_default(sock)) > 0) {
    fprintf(stderr, "%s:%d nl_recvmsgs_default failed err %d %s\n", __FILE__, __LINE__, err, strerror(err));
		goto fail_genl;
  }

	nlmsg_free(msg);

	return 0;

fail_genl:
	fprintf(stderr, "%s:%d ipvs_nl_send_message failed %s\n", __FILE__, __LINE__, strerror(errno));
	sock = NULL;
	nlmsg_free(msg);
	errno = err;
	return -1;
}

struct ip_vs_service_userspace {
    /* virtual service addresses */
    u_int16_t   protocol;
    __be32      __addr_v4;  /* virtual ip address - internal use only */
    __be16      port;
    u_int32_t   fwmark;   /* firwall mark of service */

    /* virtual service options */
    char      sched_name[IP_VS_SCHEDNAME_MAXLEN];
    unsigned    flags;    /* virtual service flags */
    unsigned    timeout;  /* persistent timeout in sec */
    __be32      netmask;  /* persistent netmask */
    u_int16_t   af; 
    union nf_inet_addr  addr;
    char      pe_name[IP_VS_PENAME_MAXLEN];
    unsigned    est_timeout;
};

typedef struct ip_vs_service_userspace ipvs_service_t;

struct ip_vs_service_userspace service = {
  .protocol = IPPROTO_TCP,
};

static int ipvs_nl_fill_service_attr(struct nl_msg *msg, ipvs_service_t *svc)
{
	struct nlattr *nl_service;
	struct ip_vs_flags flags = { .flags = svc->flags,
				     .mask = ~0 };

	nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service) {
    fprintf(stderr, "nla_nest_start failed %s\n", strerror(errno));
		return -1;
	}

	NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->fwmark) {
		NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
	} else {
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
		NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr), &(svc->addr));
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->port);
	}

	NLA_PUT_STRING(msg, IPVS_SVC_ATTR_SCHED_NAME, svc->sched_name);
	if (svc->pe_name)
		NLA_PUT_STRING(msg, IPVS_SVC_ATTR_PE_NAME, svc->pe_name);
	NLA_PUT(msg, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_TIMEOUT, svc->timeout);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_NETMASK, svc->netmask);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_EST_TIMEOUT, svc->est_timeout);

	nla_nest_end(msg, nl_service);
	return 0;

nla_put_failure:
	return -1;
}

static int ipvs_nl_noop_cb(struct nl_msg *msg, void *arg)
{
	fprintf(stderr, __func__);
	return NL_OK;
}


static int new_service()
{
	sock = nl_socket_alloc();
	if (sock == NULL)
		return -1;

  //nl_socket_set_local_port(sock, 100);
 
	if (genl_connect(sock) < 0) {
	//if (nl_connect(sock, NETLINK_USERSOCK) < 0) {
	//fprintf(stderr, "%s:%d genl_connect failed %s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}

	family = genl_ctrl_resolve(sock, IPVS_GENL_NAME);
	if (family < 0) {
		fprintf(stderr, "%s:%d genl_ops_resolve failed %d\n", __FILE__, __LINE__, family);
    return -1;
  }

  nl_socket_set_peer_port(sock, 101);

  struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_SERVICE, 0);
  //struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_GET_INFO, 0);
  if (!msg) return -1;
  if (ipvs_nl_fill_service_attr(msg, &service)) {
    fprintf(stderr, "ipvs_nl_fill_service_attr failed %s\n", strerror(errno));
    nlmsg_free(msg);
    return -1;
  }
  /*
  if (genl_send_simple(sock, family, IPVS_CMD_GET_INFO, IPVS_GENL_VERSION, 0) < 0) {
    fprintf(stderr, "ipvs_nl_fill_service_attr failed %s\n", strerror(errno));
    nlmsg_free(msg);
    return -1;
  }
  return 0;
  */

  return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
}

int main(int argc, char *argv[])
{
  if (new_service() < 0) {
    fprintf(stderr, "new_service failed %s\n", strerror(errno));
    return 1;
  }
  
	if (sock) {
    nl_socket_free(sock);
    sock = NULL;
  }
  sleep(1);
  return 0;
}
