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


/* SoftGRE context structure */
struct softgre_ctx {
	char *ip;
	struct in_addr addr;
};

/* Function declarations */
int softgre_init(struct hostapd_data *hapd);
void softgre_deinit(struct hostapd_data *hapd);
int softgre_modify_df_bit(u8 *buf, size_t len, int set_df);

#endif /* CONFIG_SOFTGRE */
#endif /* SOFTGRE_H */