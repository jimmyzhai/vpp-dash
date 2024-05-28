
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
