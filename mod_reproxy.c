/* ---------------------------------------------------------------------------
 * mod_reproxy
 *
 * An Apache2 module that implements support for the X-Reproxy-Url header, as
 * originally implemented in Danga Interactive's "perlbal" load balancer
 * (http://www.danga.com/perlbal/).
 *
 * If reproxying is enabled for a particular request (see the AllowReproxy
 * configuration setting), mod_reproxy will set X-Proxy-Capabilities to
 * "reproxy-file". A backend seeing that may respond with an X-Reproxy-Url
 * header that contains a space-delimited list of one or more URL's.
 *
 * On receiving the response from the backend, mod_reproxy will parse the
 * X-Reproxy-Url and will sequentially try each provided URL until one is
 * successful.
 *
 * The backend may include the following response headers, which will be
 * explicitly preserved in the reproxied response:
 *
 * - Content-Type
 *
 * The latest version of this module will be found here:
 *
 *   http://github.com/jamis/mod_reproxy
 *
 * ---------------------------------------------------------------------------
 * This file is distributed under the terms of the MIT license by Jamis Buck,
 * and is copyright (c) 2009 by the same. See the LICENSE file distributed
 * with this file for the complete text of the license.
 * ---------------------------------------------------------------------------
 */

#include <apr_strings.h>
#include <httpd.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_request.h>
#include <mod_proxy.h>

/* The configuration data for this module */
typedef struct reproxy_cfg {
  int enabled; /* 0 if reproxying is disabled, non-zero otherwise */
} reproxy_cfg;

/* Container describing headers that should be copied into the reproxied
 * response */
typedef struct header_fixups {
  char *content_type; /* the content-type from the original response should
                       * be preserved */
} header_fixups;

/* Information regarding the current status of the reproxy filter */
typedef struct reproxy_filter_info {
  int state; /* either FIRST_CALL, NO_REPROXY, or REPROXIED */
} reproxy_filter_info;

#define FIRST_CALL 0
#define NO_REPROXY 1
#define REPROXIED  2

static const char* reproxy_name       = "reproxy-filter";
static const char* fix_headers_filter = "reproxy-fix-headers-filter";
static const char* headers_fixed      = "reproxy-headers-fixed";

static const char* reproxy_capabilities_header = "X-Proxy-Capabilities";
static const char* reproxy_file_value = "reproxy-file";
static const char* reproxy_url_header = "X-Reproxy-Url";

static const command_rec reproxy_cmds[] = {
  AP_INIT_FLAG("AllowReproxy", ap_set_flag_slot,
    (void*)APR_OFFSETOF(reproxy_cfg, enabled), ACCESS_CONF,
    "Allow downstream handlers to request reproxying")
};

static void*         reproxy_config_init(apr_pool_t* pool, char *x);
static apr_status_t  reproxy_fixups(request_rec *r);
static void          reproxy_insert_filter(request_rec *r);
static proxy_worker* reproxy_initialize_worker(apr_pool_t *pool,
                       proxy_server_conf *conf, server_rec *server,
                       const char *url);
static apr_status_t  reproxy_request_to(request_rec *r, const char *url);
static const char*   get_reproxy_url(request_rec *r);
static int           reproxy_request(request_rec *r, const char *url_list);
static apr_status_t  reproxy_output_filter(ap_filter_t *f, apr_bucket_brigade *b);
static apr_status_t  reproxy_fix_headers_filter(ap_filter_t *f, apr_bucket_brigade *b);
static void          reproxy_hooks(apr_pool_t *pool);

module AP_MODULE_DECLARE_DATA reproxy_module = {
  STANDARD20_MODULE_STUFF,
  reproxy_config_init,
  NULL,
  NULL,
  NULL,
  reproxy_cmds,
  reproxy_hooks
};

static void*
reproxy_config_init(apr_pool_t* pool, char *x)
{
  reproxy_cfg *cfg = apr_pcalloc(pool, sizeof(reproxy_cfg));
  cfg->enabled = 0;

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

  /* if reproxying is enabled for this request, add the reproxy filter to the
   * output filters. We set state to FIRST_CALL, so that the output headers
   * will be parsed (looking for X-Reproxy-Url) the time the filter is invoked. */

  if(cfg->enabled) {
    reproxy_filter_info* info = apr_pcalloc(r->pool, sizeof(reproxy_filter_info));
    info->state = FIRST_CALL;

    ap_add_output_filter(reproxy_name, info, r, r->connection);
  }
}

/* Creates and initializes a new proxy_worker instance. Much of this is lifted
 * from different static functions in mod_proxy, so there is definitely some
 * cargo-culting going on here. I'm not sure, for instance, whether it is
 * safe (in the long run) to create and initialize workers this way, since
 * mod_proxy itself seems to assume workers are cached in a worker pool,
 * rather than created on-demand and discarded when the request finishes. */
static proxy_worker*
reproxy_initialize_worker(apr_pool_t *pool, proxy_server_conf *conf,
  server_rec *server, const char *url)
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

static const char*
get_reproxy_url(request_rec *r)
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

static int
reproxy_request(request_rec *r, const char *url_list)
{
  char *list = apr_pstrdup(r->pool, url_list);
  char *state, *url;
  int handled = 0;
  header_fixups *fixups = apr_pcalloc(r->pool, sizeof(header_fixups));

  /* remember the original declared content-type of the response, so we
   * can restore it in the reproxied response */
  fixups->content_type = apr_pstrdup(r->pool, r->content_type);

  /* remove the reproxy capabilities header, so that we don't need
   * to worry about infinite reproxy loops */
  apr_table_unset(r->headers_in, reproxy_capabilities_header);

  /* add the fix headers filter to the output filter list, so that we
   * can restore the original content_type (and, potentially, other
   * headers) to the response. */
  ap_add_output_filter(fix_headers_filter, fixups, r, r->connection);

  /* parse the url_list, which is a space-delimited list of potential
   * urls that the response may be reproxied to. */
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
  reproxy_filter_info* info = (reproxy_filter_info*)f->ctx;

  /* if this is the first time this filter has been called for this response,
   * look for the reproxy url header and act on it, if it exists. otherwise,
   * just pass the brigade to the next filter. */

  if(info->state == FIRST_CALL) {
    const char *reproxy_url = get_reproxy_url(f->r);

    if(reproxy_url) {
      info->state = REPROXIED;
      return reproxy_request(f->r, reproxy_url);
    } else {
      info->state = NO_REPROXY;
    }
  }

  return ap_pass_brigade(f->next, b);
}

static apr_status_t
reproxy_fix_headers_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
  header_fixups *fixups = (header_fixups*)f->ctx;

  /* if the headers have not yet been fixed for this response, then
   * put each saved header back into the response */

  if(!apr_table_get(f->r->notes, headers_fixed)) {
    ap_set_content_type(f->r, fixups->content_type);
    apr_table_set(f->r->notes, headers_fixed, "yes");
  }

  return ap_pass_brigade(f->next, b);
}

static void
reproxy_hooks(apr_pool_t *pool)
{
  ap_register_output_filter(reproxy_name, reproxy_output_filter, NULL, AP_FTYPE_RESOURCE);
  ap_register_output_filter(fix_headers_filter, reproxy_fix_headers_filter, NULL, AP_FTYPE_RESOURCE);
  ap_hook_fixups(reproxy_fixups, NULL, NULL, APR_HOOK_LAST);
  ap_hook_insert_filter(reproxy_insert_filter, NULL, NULL, APR_HOOK_LAST);
}
