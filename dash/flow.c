
#include <arpa/inet.h>

#include <dash/dash.h>
#include <dash/flow.h>

#define DASH_FLOW_NUM (1 << 20) /* 1M */
#define DASH_FLOW_NUM_BUCKETS (DASH_FLOW_NUM / BIHASH_KVP_PER_PAGE)
#define DASH_FLOW_MEMORY_SIZE (DASH_FLOW_NUM * 32)

static dash_flow_table_t dash_flow_table;

dash_flow_table_t*
dash_flow_table_get (void)
{
  return &dash_flow_table;
}

dash_flow_entry_t*
dash_flow_alloc()
{
    dash_flow_entry_t *flow;
    dash_flow_table_t *flow_table = dash_flow_table_get();

    pool_get (flow_table->flow_pool, flow);
    clib_memset (flow, 0, sizeof (*flow));
    flow->index = flow - flow_table->flow_pool;
    flow->timeout = DASH_FLOW_TIMEOUT;
    flow->access_time = (u64)unix_time_now();
    return flow;
}

void
dash_flow_free(dash_flow_entry_t *flow)
{
    dash_flow_table_t *flow_table = dash_flow_table_get();

    if (flow != NULL)
        pool_put(flow_table->flow_pool, flow);
}

dash_flow_entry_t*
dash_flow_get_by_index (u32 index)
{
    dash_flow_table_t *flow_table = dash_flow_table_get();
    dash_flow_entry_t *flow = pool_elt_at_index(flow_table->flow_pool, index);

    return flow;
}

static int
dash_flow_create (dash_flow_table_t *flow_table, const dash_header_t *dh)
{
    int r;
    sai_status_t status;

    ASSERT(flow_table && dh);

    u16 length = ntohs(dh->packet_meta.length);
    ASSERT(length >= offsetof(dash_header_t, flow_data));

    dash_flow_entry_t* flow = dash_flow_alloc();

    flow->key.eni = 0;
    flow->key.proto = dh->flow_key.ip_proto;
    flow->key.src_addr = dh->flow_key.src_ip.ip4;
    flow->key.dst_addr = dh->flow_key.dst_ip.ip4;
    flow->key.src_port = dh->flow_key.src_port;
    flow->key.dst_port = dh->flow_key.dst_port;

    flow->data.version = dh->flow_data.version;
    flow->data.direction = dh->flow_data.direction;
    flow->data.actions = dh->flow_data.routing_actions;

    r = dash_flow_table_add_entry (flow_table, flow);
    if (r != 0) goto table_add_entry_fail;

    status = dash_sai_create_flow_entry(dh);
    if (status != SAI_STATUS_SUCCESS) goto sai_create_flow_fail;

    flow_table->flow_stats.create_ok++;
    flow->timer_handle = TW (tw_timer_start) (&flow_table->flow_tw, flow->index, 0, flow->timeout);
    return 0;

sai_create_flow_fail:
    flow_table->flow_stats.create_fail++;
    dash_flow_table_delete_entry (flow_table, flow);
    dash_flow_free(flow);
    return -1;

table_add_entry_fail:
    return r;
}

static int
dash_flow_update (dash_flow_table_t *flow_table, const dash_header_t *dh)
{
    return -1; /* TODO later */
}

static int
dash_flow_remove (dash_flow_table_t *flow_table, const dash_header_t *dh)
{
    int r = -1;
    sai_status_t status;
    dash_flow_key_t key;
    dash_flow_entry_t* flow;

    ASSERT(flow_table && dh);

    u16 length = ntohs(dh->packet_meta.length);
    ASSERT(length >= offsetof(dash_header_t, flow_key));

    key.eni = 0;
    key.proto = dh->flow_key.ip_proto;
    key.src_addr = dh->flow_key.src_ip.ip4;
    key.dst_addr = dh->flow_key.dst_ip.ip4;
    key.src_port = dh->flow_key.src_port;
    key.dst_port = dh->flow_key.dst_port;

    flow = dash_flow_table_lookup_entry(flow_table, &key);
    if (!flow) goto flow_not_found;

    status = dash_sai_remove_flow_entry(dh);
    if (status != SAI_STATUS_SUCCESS) goto sai_remove_flow_fail;

    r = dash_flow_table_delete_entry (flow_table, flow);
    ASSERT(r == 0);
    dash_flow_free(flow);

    flow_table->flow_stats.remove_ok++;
    return 0;

sai_remove_flow_fail:
    flow_table->flow_stats.remove_fail++;

flow_not_found:
    return -1;
}

typedef int (*dash_flow_cmd_handler) (dash_flow_table_t *flow_table, const dash_header_t *dh);

static dash_flow_cmd_handler  flow_cmd_funs[] = {
    [1] = dash_flow_create,
    [2] = dash_flow_update,
    [3] = dash_flow_remove,
};


int
dash_flow_process (dash_flow_table_t *flow_table, const dash_header_t *dh)
{
    ASSERT(dh->packet_meta.packet_type == 0);
    ASSERT(dh->packet_meta.packet_subtype > 0);
    ASSERT(dh->packet_meta.packet_subtype < 4);

    return flow_cmd_funs[dh->packet_meta.packet_subtype](flow_table, dh);
}

static void
dash_flow_expired_timer_callback (u32 * expired_timers)
{
  int i;
  u32 index;
  dash_flow_table_t *flow_table = dash_flow_table_get();

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      index = expired_timers[i] & 0x7FFFFFFF;
      dash_flow_entry_t *flow = dash_flow_get_by_index(index);
      if (dash_flow_table_delete_entry (flow_table, flow) == 0) {
        dash_flow_free(flow);
      }
    }
}

void
dash_flow_table_init (dash_flow_table_t *flow_table)
{
    BV(clib_bihash_init) (&flow_table->hash_table, "flow hash table",
        DASH_FLOW_NUM_BUCKETS, DASH_FLOW_MEMORY_SIZE);

    pool_init_fixed (flow_table->flow_pool, DASH_FLOW_NUM);

    bzero(&flow_table->flow_stats, sizeof(flow_table->flow_stats));

    TW (tw_timer_wheel_init) (&flow_table->flow_tw,
                              dash_flow_expired_timer_callback,
                              1.0 /* timer interval */, 1024);
}

int
dash_flow_table_add_entry (dash_flow_table_t *flow_table, dash_flow_entry_t *flow)
{
    BVT (clib_bihash_kv) kv;

    clib_memcpy_fast (kv.key, &flow->key, sizeof(kv.key));
    kv.value = (u64)(uintptr_t)&flow->data;
    return BV (clib_bihash_add_del) (&flow_table->hash_table, &kv, 1 /* is_add */ );
}

int
dash_flow_table_delete_entry (dash_flow_table_t *flow_table, dash_flow_entry_t *flow)
{
    BVT (clib_bihash_kv) kv;

    clib_memcpy_fast (kv.key, &flow->key, sizeof(kv.key));
    return BV (clib_bihash_add_del) (&flow_table->hash_table, &kv, 0 /* is_del */ );
}

dash_flow_entry_t*
dash_flow_table_lookup_entry (dash_flow_table_t *flow_table, dash_flow_key_t *flow_key)
{
    BVT (clib_bihash_kv) kv;
    dash_flow_data_t *flow_data;

    clib_memcpy_fast (kv.key, flow_key, sizeof(kv.key));
    if (BV (clib_bihash_search) (&flow_table->hash_table, &kv, &kv))
        return NULL;

    flow_data = (dash_flow_data_t *)(uintptr_t)kv.value;
    return (dash_flow_entry_t*)((u8*)flow_data - offsetof(dash_flow_entry_t, data));
}

static uword
dash_flow_scan (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    dash_flow_table_t *flow_table = dash_flow_table_get();
    TW (tw_timer_expire_timers) (&flow_table->flow_tw, vlib_time_now(vm));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dash_flow_scan_node) = {
  .function = dash_flow_scan,
  .name = "dash-flow-scan",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
/* *INDENT-ON* */

static u8 *
dash_flow_format (u8 * s, va_list * args)
{
  dash_flow_entry_t *flow = va_arg(*args, dash_flow_entry_t*);

  s = format (s, "eni %d, proto %d, %U:%x -> %U:%x\n",
              clib_net_to_host_u16 (flow->key.eni),
              clib_net_to_host_u16 (flow->key.proto),
              format_ip4_address, &flow->key.src_addr,
              clib_net_to_host_u16 (flow->key.src_port),
              format_ip4_address, &flow->key.dst_addr,
              clib_net_to_host_u16 (flow->key.dst_port));
  s = format (s, "        data - version %u, direction %u, actions %u",
              clib_net_to_host_u32 (flow->data.version),
              clib_net_to_host_u16 (flow->data.direction),
              clib_net_to_host_u32 (flow->data.actions));
  s = format (s, "        timeout %lu",
              flow->access_time + flow->timeout - (u64)unix_time_now());

  return s;
}

typedef struct dash_flow_show_walk_ctx_t_
{
  u8 verbose;
  vlib_main_t *vm;
} dash_flow_show_walk_ctx_t;

static int
dash_flow_show_walk_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  dash_flow_show_walk_ctx_t *ctx = arg;
  dash_flow_data_t *flow_data = (dash_flow_data_t *)(uintptr_t)kvp->value;
  dash_flow_entry_t *flow = (dash_flow_entry_t*)((u8*)flow_data - offsetof(dash_flow_entry_t, data));

  vlib_cli_output (ctx->vm, "%6u: %U", flow->index, dash_flow_format, flow);
}

static clib_error_t *
dash_cmd_show_flow_fn (vlib_main_t * vm,
               unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  dash_flow_show_walk_ctx_t ctx = {
    .vm = vm,
  };
  dash_flow_table_t *flow_table = dash_flow_table_get();

  BV (clib_bihash_foreach_key_value_pair)
    (&flow_table->hash_table, dash_flow_show_walk_cb, &ctx);

  return error;
}

VLIB_CLI_COMMAND (dash_show_flow_command, static) = {
    .path = "show dash flow",
    .short_help = "show dash flow [src-addr IP]",
    .function = dash_cmd_show_flow_fn,
};

static clib_error_t *
dash_cmd_clear_flow_fn (vlib_main_t * vm,
               unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  dash_flow_table_t *flow_table = dash_flow_table_get();
  u32 index;

  if (!unformat (input, "%u", &index))
    {
      error = clib_error_return (0, "expected flow index");
      goto done;
    }


  dash_flow_entry_t *flow = dash_flow_get_by_index(index);
  if (dash_flow_table_delete_entry (flow_table, flow) == 0) {
    dash_flow_free(flow);
  }

done:
  return error;
}

VLIB_CLI_COMMAND (dash_clear_flow_command, static) = {
    .path = "clear dash flow",
    .short_help = "clear dash flow <index>",
    .function = dash_cmd_clear_flow_fn,
};


static clib_error_t *
dash_cmd_show_flow_stats_fn (vlib_main_t * vm,
               unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  dash_flow_table_t *flow_table = dash_flow_table_get();

  vlib_cli_output (vm, "%10s: %u", "create_ok",
                   flow_table->flow_stats.create_ok);
  vlib_cli_output (vm, "%10s: %u", "create_fail",
                   flow_table->flow_stats.create_fail);
  vlib_cli_output (vm, "%10s: %u", "remove_ok",
                   flow_table->flow_stats.remove_ok);
  vlib_cli_output (vm, "%10s: %u", "remove_fail",
                   flow_table->flow_stats.remove_fail);

  return error;
}

VLIB_CLI_COMMAND (dash_show_flow_stats_command, static) = {
    .path = "show dash flow stats",
    .short_help = "show dash flow [src-addr IP]",
    .function = dash_cmd_show_flow_stats_fn,
};

