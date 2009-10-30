#include <apr_strings.h>
#include <httpd.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_request.h>
#include <mod_proxy.h>

typedef struct reproxy_cfg {
  int enabled;
} reproxy_cfg;

#define FIRST_CALL NULL
#define NO_REPROXY ((void*)1)
#define REPROXIED  ((void*)2)

module AP_MODULE_DECLARE_DATA reproxy_module;

static const char* reproxy_name = "reproxy-filter";

static const char* reproxy_capabilities_header = "X-Proxy-Capabilities";
static const char* reproxy_file_value = "reproxy-file";
static const char* reproxy_url_header = "X-Reproxy-Url";

static void*
reproxy_config_init(apr_pool_t* pool, char *x)
{
  reproxy_cfg *cfg = apr_pcalloc(pool, sizeof(reproxy_cfg));
  return cfg;
}

static apr_status_t
reproxy_fixups(request_rec *r)
{
  reproxy_cfg *cfg;

  /* no reproxy handling if we're in a subrequest */
  if(r->main != NULL) {
    return DECLINED;
  }

  cfg = ap_get_module_config(r->per_dir_config, &reproxy_module);

  /* no reproxy handling if the feature is disabled */
  if(!cfg->enabled) {
    return DECLINED;
  }

  apr_table_merge(r->headers_in, reproxy_capabilities_header,
    reproxy_file_value);

  return DECLINED;;
}

static void
reproxy_insert_filter(request_rec *r)
{
  reproxy_cfg *cfg = ap_get_module_config(r->per_dir_config, &reproxy_module);

  if(cfg->enabled) {
    ap_add_output_filter(reproxy_name, NULL, r, r->connection);
  }
}

static apr_status_t
reproxy_request_to(ap_filter_t *f, apr_bucket_brigade *b, const char *url)
{
  module *mod_proxy;
  proxy_server_conf *proxy_conf;
  proxy_worker *worker;
  proxy_balancer *balancer;
  int status;

ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "loading mod_proxy.c");

  /* should probably do this during module init, so it is only done once */
  mod_proxy = ap_find_linked_module("mod_proxy.c");
  if(!mod_proxy) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "mod_proxy not loaded");
    return APR_SUCCESS;
  }

ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "getting mod_proxy config");
  proxy_conf = ap_get_module_config(f->r->server->module_config, mod_proxy);

ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "requesting ap_proxy_pre_request");
  status = ap_proxy_pre_request(&worker, &balancer, f->r, proxy_conf, (char**)&url);
  if(status != OK) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "proxy_pre_request failed with %d", status);
    return APR_SUCCESS;
  }

ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "so far, so good?");
  /* is there a way to tell apache to initialize mod_proxy, and then to grab the
   * proxy_server_conf record from mod_proxy?
   *    module *m = ap_find_linked_module("mod_proxy.c");
   *    proxy_server_conf *conf = ap_get_module_config(r->per_dir_config, m);
   *
   * ap_proxy_create_worker(apr_pool_t*)
   * ap_proxy_initialize_worker(proxy_worker*, server_rec*)
   * ap_proxy_initialize_worker_share(proxy_worker*, proxy_server_conf*, server_rec*)
   *
   * proxy_run_scheme_handler(request_rec*, proxy_worker*, proxy_server_conf*, char *url, char *proxyname, int proxyport)
   *   - if proxyname is NULL, connect directly to url
   */

  return APR_SUCCESS;
}

static const char *get_reproxy_url(request_rec *r)
{
  const char *reproxy_url = apr_table_get(r->headers_out, reproxy_url_header);

  if(reproxy_url) {
    apr_table_unset(r->headers_out, reproxy_url_header);
  } else {
    reproxy_url = apr_table_get(r->err_headers_out, reproxy_url_header);
    if(reproxy_url) {
      apr_table_unset(r->err_headers_out, reproxy_url_header);
    }
  }

  return reproxy_url;
}

static int reproxy_request(ap_filter_t *f, apr_bucket_brigade *b, const char *url_list)
{
  char *list = apr_pstrdup(f->r->pool, url_list);
  char *state, *url;
  int handled = 0;

  apr_table_unset(f->r->headers_in, reproxy_capabilities_header);

  f->ctx = REPROXIED;

  while(url = apr_strtok(list, " ", &state)) {
    list = NULL;
    if(reproxy_request_to(f, b, url) == APR_SUCCESS) {
      handled = 1;
      break;
    }
  }

  if(!handled) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_WARNING, 0, f->r, "could not reproxy to requested url(s): %s", url_list);
  }

  /* FIXME: probably want an error page if !handled, e.g. 502 or 503 */
  return ap_pass_brigade(f->next, b);
}

static apr_status_t
reproxy_output_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
  if(f->ctx == FIRST_CALL) {
    const char *reproxy_url = get_reproxy_url(f->r);

    if(reproxy_url) {
      return reproxy_request(f, b, reproxy_url);
    } else {
      f->ctx = NO_REPROXY;
    }
  } else if(f->ctx == REPROXIED) {
    return APR_SUCCESS;
  }

  return ap_pass_brigade(f->next, b);
}

static void
reproxy_hooks(apr_pool_t *pool)
{
  ap_register_output_filter(reproxy_name, reproxy_output_filter, NULL, AP_FTYPE_RESOURCE);
  ap_hook_fixups(reproxy_fixups, NULL, NULL, APR_HOOK_LAST);
  ap_hook_insert_filter(reproxy_insert_filter, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec reproxy_cmds[] = {
  AP_INIT_FLAG("AllowReproxy", ap_set_flag_slot,
    (void*)APR_OFFSETOF(reproxy_cfg, enabled), ACCESS_CONF,
    "Allow downstream handlers to request reproxying")
};

module AP_MODULE_DECLARE_DATA reproxy_module = {
  STANDARD20_MODULE_STUFF,
  reproxy_config_init,
  NULL,
  NULL,
  NULL,
  reproxy_cmds,
  reproxy_hooks
};
