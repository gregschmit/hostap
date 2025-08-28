/*
 * hostapd / SoftGRE encapsulation/decapsulation
 * Copyright (c) 2025, RG Nets, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#ifdef CONFIG_SOFTGRE

#include "utils/common.h"
#include "utils/crc32.h"
#include "hostapd.h"
#include "softgre.h"
#include "../l2_packet/l2_packet.h"
#include <netinet/ip.h>


static be16 ip_checksum(const void *buf, size_t len)
{
	u32 sum = 0;
	const u16 *pos;

	for (pos = buf; len >= 2; len -= 2)
		sum += ntohs(*pos++);
	if (len)
		sum += ntohs(*pos << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return htons(~sum);
}

/**
 * softgre_modify_df_bit - Modify Don't Fragment bit on IPv4 packets with checksum and FCS recalculation
 * @buf: Ethernet frame buffer (including FCS if present)
 * @len: Buffer length
 * @set_df: 1 to set DF bit, 0 to clear DF bit
 * Returns: 0 on success, -1 if not IPv4 or too small
 */
int softgre_modify_df_bit(u8 *buf, size_t len, int set_df)
{
	struct l2_ethhdr *eth;
	struct ip *ip_hdr;
	u16 old_frag, new_frag;
	u32 *fcs_ptr;
	u32 new_fcs;
	size_t frame_len_without_fcs;
	
	/* Minimum size: Ethernet header + IP header + FCS */
	if (len < sizeof(struct l2_ethhdr) + sizeof(struct ip) + 4)
		return -1;
	
	eth = (struct l2_ethhdr *) buf;
	if (ntohs(eth->h_proto) != 0x0800) /* Not IPv4 */
		return -1;
	
	ip_hdr = (struct ip *)(buf + sizeof(struct l2_ethhdr));
	
	old_frag = ntohs(ip_hdr->ip_off);
	if (set_df) {
		new_frag = old_frag | IP_DF; /* Set Don't Fragment bit */
	} else {
		new_frag = old_frag & ~IP_DF; /* Clear Don't Fragment bit */
	}
	
	if (old_frag != new_frag) {
		ip_hdr->ip_off = htons(new_frag);
		
		/* Recalculate IP header checksum */
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = ip_checksum(ip_hdr, ip_hdr->ip_hl << 2);
		
		/* Recalculate FCS (assume FCS is the last 4 bytes) */
		frame_len_without_fcs = len - 4;
		new_fcs = ieee80211_crc32(buf, frame_len_without_fcs);
		fcs_ptr = (u32 *)(buf + frame_len_without_fcs);
		*fcs_ptr = htonl(new_fcs);
	}
	
	return 0;
}

/**
 * softgre_init - Initialize SoftGRE for a hostapd instance
 * @hapd: hostapd BSS data
 * Returns: 0 on success, -1 on failure
 */
int softgre_init(struct hostapd_data *hapd)
{
	struct softgre_ctx *ctx;

	if (!hapd->conf->softgre_ip) {
		wpa_printf(MSG_DEBUG, "SoftGRE: No endpoint configured");
		return 0;
	}

	wpa_printf(MSG_INFO, "SoftGRE: Initializing with endpoint %s", hapd->conf->softgre_ip);

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx) { return -1; }

	ctx->ip = os_strdup(hapd->conf->softgre_ip);
	if (!ctx->ip) {
		os_free(ctx);
		return -1;
	}

	if (!inet_aton(ctx->ip, &ctx->addr)) {
		wpa_printf(MSG_ERROR, "SoftGRE: Invalid endpoint IP address");
		os_free(ctx->ip);
		os_free(ctx);
		return -1;
	}

	hapd->softgre_ctx = ctx;

	wpa_printf(
		MSG_INFO, "SoftGRE: Initialized successfully for endpoint %s", inet_ntoa(ctx->addr)
	);

	return 0;
}

/**
 * softgre_deinit - Deinitialize SoftGRE for a hostapd instance
 * @hapd: hostapd BSS data
 */
void softgre_deinit(struct hostapd_data *hapd)
{
	struct softgre_ctx *ctx = hapd->softgre_ctx;

	if (!ctx) { return; }

	wpa_printf(MSG_DEBUG, "SoftGRE: Deinitializing");

	os_free(ctx->ip);
	os_free(ctx);
	hapd->softgre_ctx = NULL;
}

#endif /* CONFIG_SOFTGRE */