#ifndef __included_flow_h__
#define __included_flow_h__

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/pool.h>
#include <vnet/ip/ip.h>

#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Default timeout in seconds */
#define DASH_FLOW_TIMEOUT   30

/* Since using bihash_16_8, its size must be 16 bytes */
typedef struct dash_flow_key {
    u16 eni;
    u16 proto;
    ip4_address_t src_addr;
    ip4_address_t dst_addr;
    u16 src_port;
    u16 dst_port;
}
__clib_packed dash_flow_key_t;

typedef struct dash_flow_data {
    u32 version;
    u16 direction;
    u32 actions;
}
__clib_packed dash_flow_data_t;

typedef struct dash_flow_entry {
    dash_flow_key_t key;
    dash_flow_data_t data;

    u32 index;

    /* timers */
    u32 timer_handle; /* index in the timer pool */
    u32 timeout;      /* in seconds */
    u64 access_time;  /* in seconds */
} dash_flow_entry_t;

typedef struct dash_flow_table {
    /* hashtable */
    BVT(clib_bihash) hash_table;

    dash_flow_entry_t *flow_pool;

    TWT (tw_timer_wheel) flow_tw;
} dash_flow_table_t;

dash_flow_table_t* dash_flow_table_get (void);
dash_flow_entry_t* dash_flow_alloc();
void dash_flow_free(dash_flow_entry_t *flow);
dash_flow_entry_t* dash_flow_get_by_index (u32 index);

void dash_flow_table_init (dash_flow_table_t *flow_table);
int dash_flow_table_add_entry (dash_flow_table_t *flow_table, dash_flow_entry_t *flow);
int dash_flow_table_delete_entry (dash_flow_table_t *flow_table, dash_flow_entry_t *flow);
dash_flow_entry_t* dash_flow_table_lookup_entry (dash_flow_table_t *flow_table, dash_flow_key_t *flow_key);

/* PIPELINE2APP metadata */
typedef struct dash_p2a_metadata {
    dash_flow_key_t flow_key;
    dash_flow_data_t flow_data;
}
__clib_packed  dash_p2a_metadata_t;

/* APP2PIPELINE metadata */
typedef struct dash_a2p_metadata {
}
__clib_packed  dash_a2p_metadata_t;

typedef enum
{
  DASH_METADATA_INVALID = 0,
  DASH_METADATA_PIPELINE2APP,
  DASH_METADATA_APP2PIPELINE,
} dash_metadata_type_t;

typedef struct dash_header {
	/* ETHER TYPE: ipv4, ipv6, ... */
	u16 type;

    /* Length of dash header */
	u8 length;

    /* Type of dash metadata: PIPELINE2APP, APP2PIPELINE */
	u8 metadata_type;

    union {
        dash_p2a_metadata_t p2a;
        dash_a2p_metadata_t a2p;
        u8 *data[0];
    };
}
__clib_packed  dash_header_t;

extern vlib_node_registration_t dash_flow_scan_node;

#endif /* __included_flow_h__ */
