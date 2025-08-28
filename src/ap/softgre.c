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
#include "utils/eloop.h"
#include "hostapd.h"
#include "softgre.h"

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