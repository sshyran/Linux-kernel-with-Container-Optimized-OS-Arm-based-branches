/* SPDX-License-Identifier: (GPL-2.0 OR MIT)
 * Google virtual Ethernet (gve) driver
 *
 * Copyright (C) 2015-2021 Google, Inc.
 */

#ifndef _GVE_DQO_H_
#define _GVE_DQO_H_

#include "gve_adminq.h"

#define GVE_ITR_ENABLE_BIT_DQO BIT(0)
#define GVE_ITR_CLEAR_PBA_BIT_DQO BIT(1)
#define GVE_ITR_NO_UPDATE_DQO (3 << 3)

#define GVE_TX_IRQ_RATELIMIT_US_DQO 50
#define GVE_RX_IRQ_RATELIMIT_US_DQO 20

netdev_tx_t gve_tx_dqo(struct sk_buff *skb, struct net_device *dev);
bool gve_tx_poll_dqo(struct gve_notify_block *block, bool do_clean);
int gve_rx_poll_dqo(struct gve_notify_block *block, int budget);
int gve_tx_alloc_rings_dqo(struct gve_priv *priv);
void gve_tx_free_rings_dqo(struct gve_priv *priv);
int gve_rx_alloc_rings_dqo(struct gve_priv *priv);
void gve_rx_free_rings_dqo(struct gve_priv *priv);
int gve_clean_tx_done_dqo(struct gve_priv *priv, struct gve_tx_ring *tx,
			  struct napi_struct *napi);
void gve_rx_post_buffers_dqo(struct gve_rx_ring *rx);
void gve_rx_write_doorbell_dqo(const struct gve_priv *priv, int queue_idx);

static inline void
gve_tx_put_doorbell_dqo(const struct gve_priv *priv,
			const struct gve_queue_resources *q_resources, u32 val)
{
	u64 index;

	index = be32_to_cpu(q_resources->db_index);
	iowrite32(val, &priv->db_bar2[index]);
}

static inline void
gve_write_irq_doorbell_dqo(const struct gve_priv *priv,
			   const struct gve_notify_block *block, u32 val)
{
	u32 index = be32_to_cpu(*block->irq_db_index);

	iowrite32(val, &priv->db_bar2[index]);
}

#endif /* _GVE_DQO_H_ */
