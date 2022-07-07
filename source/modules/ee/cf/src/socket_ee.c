/*
 * socket_ee.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#define CF_SOCKET_PRIVATE
#include "socket.h"

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "bits.h"
#include "dns.h"
#include "log.h"

#include "citrusleaf/alloc.h"

// So that we can avoid including linux/in6.h, which causes conflicts with netinet/in.h in older
// versions of glibc. It's just two definitions that we need.

#define IPV6_PREFER_SRC_PUBLIC 2
#define IPV6_ADDR_PREFERENCES 72

static bool g_advertise_ipv6 = false;
addrinfo g_cf_ip_addr_dns_hints = { .ai_flags = 0, .ai_family = 0 };

static void
check_family(const cf_ip_addr *addr)
{
	if (addr != NULL && addr->family != AF_INET && addr->family != AF_INET6) {
		cf_crash(CF_SOCKET, "Invalid address family: %d", addr->family);
	}
}

void
cf_socket_set_advertise_ipv6(bool advertise)
{
	g_advertise_ipv6 = advertise;
}

bool
cf_socket_advertises_ipv6(void)
{
	return g_advertise_ipv6;
}

int32_t
cf_ip_addr_from_addrinfo(const char *name, const addrinfo *info,
		cf_ip_addr *addrs, uint32_t *n_addrs)
{
	uint32_t i = 0;

	for (const addrinfo *walker = info; walker != NULL; walker =
			walker->ai_next) {
		if (walker->ai_socktype == SOCK_STREAM) {
			if (walker->ai_family == AF_INET) {
				if (i >= *n_addrs) {
					cf_warning(CF_SOCKET, "Too many IP addresses for '%s'",
							name);
					return -1;
				}

				struct sockaddr_in *sai = (struct sockaddr_in *)walker->ai_addr;
				addrs[i].family = AF_INET;
				addrs[i].v4 = sai->sin_addr;
				++i;
			}
			else if (walker->ai_family == AF_INET6) {
				if (i >= *n_addrs) {
					cf_warning(CF_SOCKET, "Too many IP addresses for '%s'",
							name);
					return -1;
				}

				struct sockaddr_in6 *sai6 =
						(struct sockaddr_in6 *)walker->ai_addr;
				addrs[i].family = AF_INET6;
				addrs[i].v6.s6_addr32[0] = sai6->sin6_addr.s6_addr32[0];
				addrs[i].v6.s6_addr32[1] = sai6->sin6_addr.s6_addr32[1];
				addrs[i].v6.s6_addr32[2] = sai6->sin6_addr.s6_addr32[2];
				addrs[i].v6.s6_addr32[3] = sai6->sin6_addr.s6_addr32[3];
				++i;
			}
		}
	}

	if (i == 0) {
		cf_warning(CF_SOCKET, "No valid addresses for '%s'", name);
		return -1;
	}

	cf_ip_addr_sort(addrs, i);
	*n_addrs = i;
	return 0;
}

bool
cf_ip_addr_str_is_legacy(const char *string)
{
	if (cf_ip_addr_is_dns_name(string)) {
		return true;
	}

	cf_ip_addr addr;
	CF_NEVER_FAILS(cf_ip_addr_from_string(string, &addr));
	return addr.family == AF_INET;
}

bool
cf_ip_addr_is_legacy(const cf_ip_addr *addr)
{
	return addr->family == AF_INET;
}

bool
cf_ip_addr_legacy_only(void)
{
	return ! g_advertise_ipv6;
}

int32_t
cf_ip_addr_to_string(const cf_ip_addr *addr, char *string, size_t size)
{
	check_family(addr);
	const char *res;

	if (addr->family == AF_INET) {
		res = inet_ntop(AF_INET, &addr->v4, string, size);
	} else {
		res = inet_ntop(AF_INET6, &addr->v6, string, size);
	}

	if (res == NULL) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	return strlen(string);
}

int32_t
cf_ip_addr_from_binary(const uint8_t *binary, size_t size, cf_ip_addr *addr)
{
	if (size < 4 || (size > 4 && size < 16)) {
		cf_warning(CF_SOCKET, "Input buffer underflow");
		return -1;
	}

	bool v4 = (size == 4);

	if (v4) {
		addr->family = AF_INET;
		memcpy(&addr->v4, binary, 4);
		return 4;
	}

	addr->family = AF_INET6;
	memcpy(&addr->v6, binary, 16);

	return 16;
}

int32_t
cf_ip_addr_to_binary(const cf_ip_addr *addr, uint8_t *binary, size_t size)
{
	check_family(addr);

	size_t expected_size = (addr->family == AF_INET) ? 4 : 16;
	if (size < expected_size) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	if (addr->family == AF_INET) {
		memcpy(binary, &addr->v4, 4);
	} else {
		memcpy(binary, &addr->v6, 16);
	}

	return 16;
}

int32_t
cf_ip_addr_compare(const cf_ip_addr *lhs, const cf_ip_addr *rhs)
{
	check_family(lhs);
	check_family(rhs);

	if (lhs->family != rhs->family) {
		return (int32_t)lhs->family - (int32_t)rhs->family;
	}

	if (lhs->family == AF_INET) {
		return memcmp(&lhs->v4, &rhs->v4, 4);
	}

	return memcmp(&lhs->v6, &rhs->v6, 16);
}

void
cf_ip_addr_copy(const cf_ip_addr *from, cf_ip_addr *to)
{
	check_family(from);

	if (from->family == AF_INET) {
		to->family = AF_INET;
		to->v4 = from->v4;
	}
	else {
		to->family = AF_INET6;
		to->v6.s6_addr32[0] = from->v6.s6_addr32[0];
		to->v6.s6_addr32[1] = from->v6.s6_addr32[1];
		to->v6.s6_addr32[2] = from->v6.s6_addr32[2];
		to->v6.s6_addr32[3] = from->v6.s6_addr32[3];
	}
}

void
cf_ip_addr_set_local(cf_ip_addr *addr)
{
	addr->family = AF_INET;
	addr->v4.s_addr = htonl(0x7f000001);
}

bool
cf_ip_addr_is_local(const cf_ip_addr *addr)
{
	check_family(addr);

	if (addr->family == AF_INET) {
		return (ntohl(addr->v4.s_addr) & 0xff000000) == 0x7f000000;
	}

	return IN6_IS_ADDR_LOOPBACK(&addr->v6);
}

void
cf_ip_addr_set_any(cf_ip_addr *addr)
{
	addr->family = AF_INET;
	addr->v4.s_addr = 0;
}

bool
cf_ip_addr_is_any(const cf_ip_addr *addr)
{
	check_family(addr);

	if (addr->family == AF_INET) {
		return addr->v4.s_addr == 0;
	}

	return (addr->v6.s6_addr32[0] | addr->v6.s6_addr32[1] |
			addr->v6.s6_addr32[2] | addr->v6.s6_addr32[3]) == 0;
}

int32_t
cf_ip_net_from_string(const char *string, cf_ip_net *net)
{
	size_t len = strlen(string);
	char net_string[len + 1];

	strcpy(net_string, string);

	char *slash = strchr(net_string, '/');

	if (slash != NULL) {
		*slash = 0;
	}

	if (inet_pton(AF_INET, net_string, &net->addr.v4) == 1) {
		net->family = AF_INET;
	}
	else if (inet_pton(AF_INET6, net_string, &net->addr.v6) == 1) {
		net->family = AF_INET6;
	}
	else {
		cf_warning(CF_SOCKET, "Invalid IP address %s", net_string);
		return -1;
	}

	uint32_t max_prefix_bits = net->family == AF_INET ? 32 : 128;
	uint32_t prefix_bits;

	if (slash == NULL) {
		prefix_bits = max_prefix_bits;
	}
	else {
		char *end;
		prefix_bits = strtoul(slash + 1, &end, 10);

		if (*end != 0 || prefix_bits > max_prefix_bits) {
			cf_warning(CF_SOCKET, "Invalid network address %s", string);
			return -1;
		}
	}

	uint8_t *mask = (uint8_t *)&net->mask;

	memset(mask, 0, sizeof(net->mask));

	while (prefix_bits >= 8) {
		*mask++ = 0xff;
		prefix_bits -= 8;
	}

	*mask = (uint8_t)(0xff << (8 - prefix_bits));

	if (net->family == AF_INET) {
		if ((net->addr.v4.s_addr & ~net->mask.v4.s_addr) != 0) {
			cf_warning(CF_SOCKET, "Invalid IPv4 network address %s", string);
			return -1;
		}

		return 0;
	}
	// else - IPv6.

	uint32_t *mask32 = net->mask.v6.s6_addr32;
	uint32_t *net32 = net->addr.v6.s6_addr32;

	if ((net32[0] & ~mask32[0]) != 0 || (net32[1] & ~mask32[1]) != 0 ||
			(net32[2] & ~mask32[2]) != 0 || (net32[3] & ~mask32[3]) != 0) {
		cf_warning(CF_SOCKET, "Invalid IPv6 network address %s", string);
		return -1;
	}

	return 0;
}

int32_t
cf_ip_net_to_string(const cf_ip_net *net, char *string, size_t size)
{
	const char *res;
	uint32_t max_prefix_bits;
	uint32_t prefix_bits;

	if (net->family == AF_INET) {
		res = inet_ntop(AF_INET, &net->addr.v4, string, size);
		max_prefix_bits = 32;
		prefix_bits = cf_bit_count64(net->mask.v4.s_addr);
	}
	else {
		res = inet_ntop(AF_INET6, &net->addr.v6, string, size);
		max_prefix_bits = 128;

		const uint32_t *mask32 = net->mask.v6.s6_addr32;

		prefix_bits = cf_bit_count64(mask32[0]) + cf_bit_count64(mask32[1]) +
				cf_bit_count64(mask32[2]) + cf_bit_count64(mask32[3]);
	}

	if (res == NULL) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	size_t len = strlen(string);

	if (prefix_bits < max_prefix_bits) {
		size_t room = size - len;
		int added = snprintf(string + len, room, "/%u", prefix_bits);

		if (added >= room) {
			cf_warning(CF_SOCKET, "Output buffer overflow");
			return -1;
		}

		len += added;
	}

	return (int32_t)len;
}

bool
cf_ip_net_contains(const cf_ip_net *net, const cf_ip_addr *addr)
{
	if (net->family != addr->family) {
		return false;
	}

	if (net->family == AF_INET) {
		return (addr->v4.s_addr & net->mask.v4.s_addr) == net->addr.v4.s_addr;
	}

	const uint32_t *mask32 = net->mask.v6.s6_addr32;
	const uint32_t *net32 = net->addr.v6.s6_addr32;

	const uint32_t *addr32 = addr->v6.s6_addr32;

	return (addr32[0] & mask32[0]) == net32[0] &&
			(addr32[1] & mask32[1]) == net32[1] &&
			(addr32[2] & mask32[2]) == net32[2] &&
			(addr32[3] & mask32[3]) == net32[3];
}

int32_t
cf_sock_addr_to_string(const cf_sock_addr *addr, char *string, size_t size)
{
	check_family(&addr->addr);
	int32_t total = 0;

	if (addr->addr.family == AF_INET6) {
		if (size - total < 2) {
			cf_warning(CF_SOCKET, "Output buffer overflow");
			return -1;
		}

		string[total++] = '[';
		string[total] = 0;
	}

	int32_t count = cf_ip_addr_to_string(&addr->addr, string + total, size - total);

	if (count < 0) {
		return -1;
	}

	total += count;

	if (addr->addr.family == AF_INET6) {
		if (size - total < 2) {
			cf_warning(CF_SOCKET, "Output buffer overflow");
			return -1;
		}

		string[total++] = ']';
		string[total] = 0;
	}

	if (size - total < 2) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	string[total++] = ':';
	string[total] = 0;

	count = cf_ip_port_to_string(addr->port, string + total, size - total);

	if (count < 0) {
		return -1;
	}

	total += count;
	return total;
}

void
cf_sock_addr_from_native(const struct sockaddr *native, cf_sock_addr *addr)
{
	if (native->sa_family == AF_INET) {
		struct sockaddr_in *sai = (struct sockaddr_in *)native;
		addr->addr.family = AF_INET;
		addr->addr.v4 = sai->sin_addr;
		addr->port = ntohs(sai->sin_port);
		return;
	}

	if (native->sa_family == AF_INET6) {
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)native;
		addr->addr.family = AF_INET6;
		addr->addr.v6.s6_addr32[0] = sai6->sin6_addr.s6_addr32[0];
		addr->addr.v6.s6_addr32[1] = sai6->sin6_addr.s6_addr32[1];
		addr->addr.v6.s6_addr32[2] = sai6->sin6_addr.s6_addr32[2];
		addr->addr.v6.s6_addr32[3] = sai6->sin6_addr.s6_addr32[3];
		addr->port = ntohs(sai6->sin6_port);
		return;
	}

	cf_crash(CF_SOCKET, "Invalid address family: %d", native->sa_family);
}

void
cf_sock_addr_to_native(const cf_sock_addr *addr, struct sockaddr *native)
{
	check_family(&addr->addr);

	if (addr->addr.family == AF_INET) {
		struct sockaddr_in *sai = (struct sockaddr_in *)native;
		memset(sai, 0, sizeof(struct sockaddr_in));
		sai->sin_family = AF_INET;
		sai->sin_addr = addr->addr.v4;
		sai->sin_port = htons(addr->port);
		return;
	}

	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)native;
	memset(sai6, 0, sizeof(struct sockaddr_in6));
	sai6->sin6_family = AF_INET6;
	sai6->sin6_addr.s6_addr32[0] = addr->addr.v6.s6_addr32[0];
	sai6->sin6_addr.s6_addr32[1] = addr->addr.v6.s6_addr32[1];
	sai6->sin6_addr.s6_addr32[2] = addr->addr.v6.s6_addr32[2];
	sai6->sin6_addr.s6_addr32[3] = addr->addr.v6.s6_addr32[3];
	sai6->sin6_port = htons(addr->port);
}

int32_t
cf_mserv_cfg_add_combo(cf_mserv_cfg *serv_cfg, cf_sock_owner owner, cf_ip_port port,
		cf_ip_addr *addr, cf_ip_addr *if_addr, uint8_t ttl)
{
	cf_msock_cfg sock_cfg;
	cf_msock_cfg_init(&sock_cfg, owner);
	sock_cfg.port = port;
	sock_cfg.ttl = ttl;

	if (!cf_ip_addr_is_any(if_addr)) {
		if (cf_ip_addr_is_legacy(if_addr) != cf_ip_addr_is_legacy(addr)) {
			return 0;
		}

		cf_ip_addr_copy(addr, &sock_cfg.addr);
		cf_ip_addr_copy(if_addr, &sock_cfg.if_addr);
		return cf_mserv_cfg_add_msock_cfg(serv_cfg, &sock_cfg);
	}

	if (cf_ip_addr_is_legacy(addr)) {
		cf_ip_addr_copy(addr, &sock_cfg.addr);

		sock_cfg.if_addr.family = AF_INET;
		sock_cfg.if_addr.v4.s_addr = 0;

		return cf_mserv_cfg_add_msock_cfg(serv_cfg, &sock_cfg);
	}

	cf_ip_addr_copy(addr, &sock_cfg.addr);

	sock_cfg.if_addr.family = AF_INET6;
	sock_cfg.if_addr.v6.s6_addr32[0] = 0;
	sock_cfg.if_addr.v6.s6_addr32[1] = 0;
	sock_cfg.if_addr.v6.s6_addr32[2] = 0;
	sock_cfg.if_addr.v6.s6_addr32[3] = 0;

	return cf_mserv_cfg_add_msock_cfg(serv_cfg, &sock_cfg);
}

int32_t
cf_socket_mcast_set_inter(cf_socket *sock, const cf_ip_addr *iaddr)
{
	check_family(iaddr);

	cf_detail(CF_SOCKET, "Setting multicast interface for FD %d to %s",
			sock->fd, cf_ip_addr_print(iaddr));

	cf_sock_addr local;

	if (cf_socket_local_name(sock, &local) < 0) {
		return -1;
	}

	if (local.addr.family != iaddr->family) {
		cf_warning(CF_SOCKET, "IPv4/IPv6 address type mismatch");
		return -1;
	}

	if (iaddr->family == AF_INET) {
		struct ip_mreqn mr;
		memset(&mr, 0, sizeof(mr));
		mr.imr_address = iaddr->v4;

		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_IF, &mr, sizeof(mr)) < 0) {
			cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_IF) failed on FD %d: %d (%s)",
					sock->fd, errno, cf_strerror(errno));
			return -1;
		}

		return 0;
	}

	char *name;
	int32_t inter;

	if (cf_inter_addr_to_index_and_name(iaddr, &inter, &name) < 0) {
		cf_warning(CF_SOCKET, "No interface found for IP address %s", cf_ip_addr_print(iaddr));
		return -1;
	}

	cf_detail(CF_SOCKET, "Interface name is %s, index is %d", name, inter);
	cf_free(name);

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &inter, sizeof(inter)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IPV6_MULTICAST_IF) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

	return 0;
}

int32_t
cf_socket_mcast_set_ttl(cf_socket *sock, int32_t ttl)
{
	cf_sock_addr local;

	if (cf_socket_local_name(sock, &local) < 0) {
		return -1;
	}

	if (local.addr.family == AF_INET) {
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
			cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_TTL) failed on FD %d: %d (%s)",
					sock->fd, errno, cf_strerror(errno));
			return -1;
		}

		return 0;
	}

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IPV6_MULTICAST_HOPS) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

	return 0;
}

int32_t
cf_socket_mcast_join_group(cf_socket *sock, const cf_ip_addr *iaddr, const cf_ip_addr *gaddr)
{
	check_family(iaddr);
	check_family(gaddr);

	if (iaddr->family != gaddr->family) {
		cf_warning(CF_SOCKET, "IPv4/IPv6 address type mismatch");
		return -1;
	}

	if (cf_log_check_level(CF_SOCKET, CF_DETAIL)) {
		char tmp[1000] = "<none>";

		if (!cf_ip_addr_is_any(iaddr)) {
			cf_ip_addr_to_string_safe(iaddr, tmp, sizeof(tmp));
		}

		cf_detail(CF_SOCKET, "FD %d joining multicast group %s/%s",
				sock->fd, tmp, cf_ip_addr_print(gaddr));
	}

	if (gaddr->family == AF_INET) {
		struct ip_mreqn mr;
		memset(&mr, 0, sizeof(mr));

		if (!cf_ip_addr_is_any(iaddr)) {
			mr.imr_address = iaddr->v4;
		}

		mr.imr_multiaddr = gaddr->v4;

		if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
			cf_warning(CF_SOCKET, "setsockopt(IP_ADD_MEMBERSHIP) failed on FD %d: %d (%s)",
					sock->fd, errno, cf_strerror(errno));
			return -1;
		}

#ifdef IP_MULTICAST_ALL
		// Only receive traffic from multicast groups this socket actually joins.
		// Note: Bind address filtering takes precedence, so this is simply an extra level of
		// restriction.
		static const int32_t no = 0;

		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_ALL, &no, sizeof(no)) < 0) {
			cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_ALL) failed on FD %d: %d (%s)",
					sock->fd, errno, cf_strerror(errno));
			return -1;
		}
#endif

		return 0;
	}

	struct ipv6_mreq mr;
	memset(&mr, 0, sizeof(mr));

	if (!cf_ip_addr_is_any(iaddr)) {
		char *name;
		int32_t inter;

		if (cf_inter_addr_to_index_and_name(iaddr, &inter, &name) < 0) {
			cf_warning(CF_SOCKET, "No interface found for IP address %s", cf_ip_addr_print(iaddr));
			return -1;
		}

		cf_detail(CF_SOCKET, "Interface name is %s, index is %d", name, inter);
		cf_free(name);

		mr.ipv6mr_interface = (uint32_t)inter;
	}

	mr.ipv6mr_multiaddr.s6_addr32[0] = gaddr->v6.s6_addr32[0];
	mr.ipv6mr_multiaddr.s6_addr32[1] = gaddr->v6.s6_addr32[1];
	mr.ipv6mr_multiaddr.s6_addr32[2] = gaddr->v6.s6_addr32[2];
	mr.ipv6mr_multiaddr.s6_addr32[3] = gaddr->v6.s6_addr32[3];

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IPV6_ADD_MEMBERSHIP) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

	return 0;
}

size_t
cf_socket_addr_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);

	default:
		cf_crash(CF_SOCKET, "Invalid address family: %d", sa->sa_family);
		return 0;
	}
}

int32_t
cf_socket_parse_netlink(bool allow_ipv6, uint32_t family, uint32_t flags,
		const void *data, size_t len, cf_ip_addr *addr)
{
	cf_detail(CF_SOCKET, "Netlink address with family %u, length %zu",
			family, len);

	if (family == AF_INET) {
		if (len != 4) {
			cf_detail(CF_SOCKET, "Invalid IPv4 address");
			return -1;
		}

		addr->family = AF_INET;
		memcpy(&addr->v4, data, 4);
		cf_detail(CF_SOCKET, "IPv4 address OK");
		return 0;
	}

	if (family != AF_INET6) {
		cf_detail(CF_SOCKET, "Unknown address family");
		return -1;
	}

	if (len != 16 || !allow_ipv6) {
		cf_detail(CF_SOCKET, "Invalid IPv6 address or IPv6 not allowed");
		return -1;
	}

	if (IN6_IS_ADDR_LINKLOCAL(data)) {
		cf_detail(CF_SOCKET, "Skipping invalid IPV6 address class");
		return -1;
	}

	if ((flags & IFA_F_TEMPORARY) != 0) {
		cf_detail(CF_SOCKET, "Skipping temporary IPv6 address");
		return -1;
	}

	addr->family = AF_INET6;
	memcpy(&addr->v6, data, 16);
	return 0;
}

void
cf_socket_fix_client(cf_socket *sock)
{
	cf_sock_addr local;

	if (cf_socket_local_name(sock, &local) < 0) {
		cf_crash(CF_SOCKET, "Error while determining address family");
	}

	if (local.addr.family != AF_INET6) {
		return;
	}

	static uint32_t pref = IPV6_PREFER_SRC_PUBLIC;

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &pref, sizeof(pref)) < 0) {
		// Only available from Linux 2.6.26.
		if (errno != ENOPROTOOPT) {
			cf_crash(CF_SOCKET, "setsockopt(IPV6_ADDR_PREFERENCES) failed on FD %d: %d (%s)",
					sock->fd, errno, cf_strerror(errno));
		}

		cf_warning(CF_SOCKET, "Kernel does not support IPV6_ADDR_PREFERENCES");
	}
}

static bool
kernel_has_ipv6(void)
{
	int32_t fd = socket(PF_INET6, SOCK_STREAM, 0);

	if (fd < 0) {
		if (errno != EAFNOSUPPORT) {
			cf_crash(CF_SOCKET, "Error while creating IPv6 test socket: %d (%s)",
					errno, cf_strerror(errno));
		}

		return false;
	}

	static struct sockaddr_in6 loc = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};

	if (bind(fd, (struct sockaddr *)&loc, sizeof(loc)) < 0) {
		if (errno != EADDRNOTAVAIL) {
			cf_crash(CF_SOCKET, "Error while binding IPv6 test socket: %d (%s)",
					errno, cf_strerror(errno));
		}

		close(fd);
		return false;
	}

	close(fd);
	return true;
}

void
cf_socket_fix_bind(cf_serv_cfg *serv_cfg)
{
	for (int32_t owner = 0; owner < CF_SOCK_OWNER_INVALID; ++owner) {
		cf_sock_cfg *loc4 = NULL;
		cf_sock_cfg *loc6 = NULL;
		cf_sock_cfg *any4 = NULL;
		cf_sock_cfg *any6 = NULL;

		for (uint32_t i = 0; i < serv_cfg->n_cfgs; ++i) {
			cf_sock_cfg *sock_cfg = &serv_cfg->cfgs[i];

			if (sock_cfg->owner != owner) {
				continue;
			}

			cf_ip_addr *addr = &sock_cfg->addr;

			if (addr->family == AF_INET) {
				if (cf_ip_addr_is_local(addr)) {
					loc4 = sock_cfg;
				}
				else if (cf_ip_addr_is_any(addr)) {
					any4 = sock_cfg;
				}
			}
			else if (addr->family == AF_INET6) {
				if (cf_ip_addr_is_local(addr)) {
					loc6 = sock_cfg;
				}
				else if (cf_ip_addr_is_any(addr)) {
					any6 = sock_cfg;
				}
			}
		}

		cf_sock_cfg sock_cfg;

		if (loc4 != NULL && loc6 == NULL && kernel_has_ipv6()) {
			cf_sock_cfg_copy(loc4, &sock_cfg);

			sock_cfg.addr.family = AF_INET6;
			sock_cfg.addr.v6.s6_addr32[0] = 0;
			sock_cfg.addr.v6.s6_addr32[1] = 0;
			sock_cfg.addr.v6.s6_addr32[2] = 0;
			sock_cfg.addr.v6.s6_addr32[3] = htonl(0x00000001);

			CF_NEVER_FAILS(cf_serv_cfg_add_sock_cfg(serv_cfg, &sock_cfg));
		}
		else if (loc4 == NULL && loc6 != NULL) {
			cf_sock_cfg_copy(loc6, &sock_cfg);

			sock_cfg.addr.family = AF_INET;
			sock_cfg.addr.v4.s_addr = htonl(0x7f000001);

			CF_NEVER_FAILS(cf_serv_cfg_add_sock_cfg(serv_cfg, &sock_cfg));
		}

		if (any4 != NULL && any6 == NULL && kernel_has_ipv6()) {
			cf_sock_cfg_copy(any4, &sock_cfg);

			sock_cfg.addr.family = AF_INET6;
			sock_cfg.addr.v6.s6_addr32[0] = 0;
			sock_cfg.addr.v6.s6_addr32[1] = 0;
			sock_cfg.addr.v6.s6_addr32[2] = 0;
			sock_cfg.addr.v6.s6_addr32[3] = 0;

			CF_NEVER_FAILS(cf_serv_cfg_add_sock_cfg(serv_cfg, &sock_cfg));
		}
		else if (any4 == NULL && any6 != NULL) {
			cf_sock_cfg_copy(any6, &sock_cfg);

			sock_cfg.addr.family = AF_INET;
			sock_cfg.addr.v4.s_addr = 0;

			CF_NEVER_FAILS(cf_serv_cfg_add_sock_cfg(serv_cfg, &sock_cfg));
		}
	}
}

void
cf_socket_fix_server(cf_socket *sock)
{
	cf_sock_addr local;

	if (cf_socket_local_name(sock, &local) < 0) {
		cf_crash(CF_SOCKET, "Error while determining address family");
	}

	if (local.addr.family != AF_INET6) {
		return;
	}

	static uint32_t yes = 1;

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) < 0) {
		cf_crash(CF_SOCKET, "setsockopt(IPV6_V6ONLY) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
	}
}
