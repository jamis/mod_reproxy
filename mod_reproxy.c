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

typedef struct header_fixups {
  char *content_type;
} header_fixups;

#define FIRST_CALL NULL
#define NO_REPROXY ((void*)1)
#define REPROXIED  ((void*)2)

module AP_MODULE_DECLARE_DATA reproxy_module;

static const char* reproxy_name = "reproxy-filter";
static const char* unset_filter = "reproxy-unset-headers-filter";

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

static proxy_worker*
reproxy_initialize_worker(apr_pool_t *pool, proxy_server_conf *conf, server_rec *server, const char *url)
{
  proxy_worker *worker;
  apr_status_t status;
  apr_uri_t uri;

  status = apr_uri_parse(pool, url, &uri);
  if(status != APR_SUCCESS) {
    ap_log_error(__FILE__, __LINE__, APLOG_ERR, status, server, "could not parse url: %s", url);
    return NULL;
  }

  if(!uri.hostname || !uri.scheme) {
    ap_log_error(__FILE__, __LINE__, APLOG_ERR, status, server, "URL must be absolute: %s", url);
    return NULL;
  }

  worker = ap_proxy_create_worker(pool);

  ap_str_tolower(uri.hostname);
  ap_str_tolower(uri.scheme);

  worker->name = apr_pstrcat(pool, "reproxy:", apr_uri_unparse(pool, &uri, APR_URI_UNP_REVEALPASSWORD), NULL);
  worker->scheme = uri.scheme;
  worker->hostname = uri.hostname;
  worker->port = uri.port;
  worker->flush_packets = flush_off;
  worker->flush_wait = PROXY_FLUSH_WAIT;

  ap_proxy_initialize_worker_share(conf, worker, server);

  status = ap_proxy_initialize_worker(worker, server);
  if(status != APR_SUCCESS) {
    ap_log_error(__FILE__, __LINE__, APLOG_ERR, status, server, "could not initialize worker (%d)", status);
    return NULL;
  }

  return worker;
}

static apr_status_t
reproxy_request_to(request_rec *r, const char *url)
{
  module *mod_proxy;
  proxy_server_conf *proxy_conf;
  proxy_worker *worker = NULL;
  int status;

  /* should probably do this during module init, so it is only done once */
  mod_proxy = ap_find_linked_module("mod_proxy.c");
  if(!mod_proxy) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_ERR, 0, r, "mod_proxy not loaded");
    return -1;
  }

  proxy_conf = ap_get_module_config(r->server->module_config, mod_proxy);

  worker = reproxy_initialize_worker(r->pool, proxy_conf, r->server, url);
  if(!worker) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_ERR, 0, r, "couldn't initialize worker");
    return -1;
  }

  status = proxy_run_scheme_handler(r, worker, proxy_conf, (char*)url, NULL, 0);
  ap_log_rerror(__FILE__, __LINE__, APLOG_ERR, 0, r, "proxy finished with %d", status);

  return status;
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

static int reproxy_request(request_rec *r, const char *url_list)
{
  char *list = apr_pstrdup(r->pool, url_list);
  char *state, *url;
  int handled = 0;
  header_fixups *fixups = apr_pcalloc(r->pool, sizeof(header_fixups));

ap_log_rerror(__FILE__, __LINE__, APLOG_DEBUG, 0, r, "BEFORE: content-type is >%s<", r->content_type);
  fixups->content_type = apr_pstrdup(r->pool, r->content_type);

  apr_table_unset(r->headers_in, reproxy_capabilities_header);
  ap_add_output_filter(unset_filter, fixups, r, r->connection);

  while(url = apr_strtok(list, " ", &state)) {
    list = NULL;
    if(reproxy_request_to(r, url) == APR_SUCCESS) {
      handled = 1;
      break;
    }
  }

  if(!handled) {
    ap_log_rerror(__FILE__, __LINE__, APLOG_ERR, 0, r, "could not reproxy to requested url(s): %s", url_list);
    ap_die(HTTP_BAD_GATEWAY, r);
    return -1;
  }

  return APR_SUCCESS;
}

static apr_status_t
reproxy_output_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
  if(f->ctx == FIRST_CALL) {
    const char *reproxy_url = get_reproxy_url(f->r);

    if(reproxy_url) {
      return reproxy_request(f->r, reproxy_url);
    } else {
      f->ctx = NO_REPROXY;
    }
  } else if(f->ctx == REPROXIED) {
    return APR_SUCCESS;
  }

  return ap_pass_brigade(f->next, b);
}

static apr_status_t
reproxy_unset_headers_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
  header_fixups *fixups = (header_fixups*)f->ctx;

ap_log_error(__FILE__, __LINE__, APLOG_DEBUG, 0, f->r->server, "original content_type: %s", fixups->content_type);
  ap_set_content_type(f->r, fixups->content_type);
  return ap_pass_brigade(f->next, b);
}

static void
reproxy_hooks(apr_pool_t *pool)
{
  ap_register_output_filter(reproxy_name, reproxy_output_filter, NULL, AP_FTYPE_RESOURCE);
  ap_register_output_filter(unset_filter, reproxy_unset_headers_filter, NULL, AP_FTYPE_RESOURCE);
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
