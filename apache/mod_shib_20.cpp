
/* mod_shib_20.cpp -- a wrapper around the apache module code to
 * 		      build for Apache 2.0
 *
 * Created by:  Derek Atkins <derek@ihtfp.com>
 *
 */

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#include <http_request.h>
#include <apr_strings.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>
#include <apr_pools.h>

#define SHIB_APACHE_20 1

#define MODULE_VAR_EXPORT AP_MODULE_DECLARE_DATA
#define SH_AP_POOL apr_pool_t
#define SH_AP_TABLE apr_table_t
#define SH_AP_CONFIGFILE ap_configfile_t
#define array_header apr_array_header_t

#define SH_AP_R(r) 0,r
#define SH_AP_USER(r) r->user

#define SERVER_ERROR HTTP_INTERNAL_SERVER_ERROR
#define REDIRECT HTTP_MOVED_TEMPORARILY
#define ap_pcalloc apr_pcalloc
#define ap_pstrdup apr_pstrdup
#define ap_pstrcat apr_pstrcat
#define ap_psprintf apr_psprintf
#define ap_table_get apr_table_get
#define ap_table_setn apr_table_setn
#define ap_table_unset apr_table_unset
#define ap_table_set apr_table_set
#define ap_clear_pool apr_pool_clear
#define ap_destroy_pool apr_pool_destroy
#define ap_make_table apr_table_make

#define ap_send_http_header(r)
#define ap_hard_timeout(str,r)
#define ap_kill_timeout(r)

#include "mod_apache.cpp"
