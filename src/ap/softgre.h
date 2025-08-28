/*
 * hostapd / SoftGRE encapsulation/decapsulation
 * Copyright (c) 2025, RG Nets, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SOFTGRE_H
#define SOFTGRE_H

#ifdef CONFIG_SOFTGRE

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"

/* GRE header structure */
struct gre_header {
	u16 flags_version;
	u16 protocol;
} __attribute__((__packed__));

#define GRE_FLAG_CHECKSUM	0x8000
#define GRE_FLAG_ROUTING	0x4000  
#define GRE_FLAG_KEY		0x2000
#define GRE_FLAG_SEQ		0x1000
#define GRE_FLAG_STRICT_ROUTE	0x0800
#define GRE_FLAG_VERSION_MASK	0x0007

#define GRE_PROTOCOL_ETH	0x6558
#define GRE_VERSION		0x0000

/* SoftGRE context structure */
struct softgre_ctx {
	char *ip;
	struct in_addr addr;
};

/* Function declarations */
int softgre_init(struct hostapd_data *hapd);
void softgre_deinit(struct hostapd_data *hapd);

#endif /* CONFIG_SOFTGRE */
#endif /* SOFTGRE_H */