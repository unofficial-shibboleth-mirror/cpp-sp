
/* mod_shib_13.cpp -- a wrapper around the apache module code to
 * 		      build for Apache 1.3
 *
 * Created by:  Derek Atkins <derek@ihtfp.com>
 *
 */

#undef _XPG4_2

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>

#define SHIB_APACHE_13 1

#define SH_AP_POOL pool
#define SH_AP_TABLE table
#define SH_AP_CONFIGFILE configfile_t
#define SH_AP_R(r) r
#define SH_AP_USER(r) r->connection->user

#define apr_pool_userdata_setn(n,k,d,p)
#define apr_pool_cleanup_register(p1,p2,f,d)

#include "mod_apache.cpp"
