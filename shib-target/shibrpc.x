/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * shibrpc.x: generic shib RPC definitions for target communication
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 * Modified By: Scott Cantor <cantor.2@osu.edu>
 *
 * $Id$
 */

#ifdef RPC_XDR
%
%/* sometimes xdr_enum_t is not defined properly */
%#ifndef xdr_enum_t
%#define xdr_enum_t xdr_enum
%#endif
%
#endif

struct shibrpc_args_3 {
  string	xml<>;						/* WDDX XML input message */
};

struct shibrpc_ret_3 {
  string	xml<>;						/* WDDX XML output message */
};


/* Define the Shib Target RPC interface */
program SHIBRPC_PROG {
  version SHIBRPC_VERS_3 {

    shibrpc_ret_3 shibrpc_call (shibrpc_args_3) = 3;

  } = 3;
} = 123456;			/* Arbitrary RPC Program Number */
