/*
 * shar-utils.h -- header file for the SHAR utilities.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHAR_UTILS_H
#define SHAR_UTILS_H

#include <shib-target/shib-target.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  u_long prog;
  u_long vers;
  void (*dispatch)();
} ShibRPCProtocols;


int shar_create_svc(ShibSocket sock,const ShibRPCProtocols protos[],int numprotos);
void shar_new_connection(ShibSocket sock, const ShibRPCProtocols protos[],
			 int numprotos);
void shar_utils_init();
void shar_utils_fini();

#ifdef __cplusplus
}
#endif

#endif /* SHAR_UTILS_H */
