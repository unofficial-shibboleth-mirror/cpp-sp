/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-rpchandle.cpp -- the RPC Handle abstraction
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
#endif

#include "shib-target.h"
#include <shib/shib-threads.h>

#include <log4cpp/Category.hh>

#include <stdexcept>

using namespace std;
using namespace shibboleth;
using namespace shibtarget;


class shibtarget::RPCHandleInternal
{
public:
  RPCHandleInternal();
  ~RPCHandleInternal() { delete mutex; }

  CLIENT *	m_clnt;
  ShibSocket	m_sock;

  ShibSockName m_shar;
  u_long	m_program;
  u_long	m_version;

  log4cpp::Category* log;
  Mutex*	mutex;
};

RPCHandleInternal::RPCHandleInternal()
{
  string ctx = "shibtarget.RPCHandle";
  log = &(log4cpp::Category::getInstance(ctx));
  m_clnt = NULL;
  mutex = Mutex::create();
}

//*************************************************************************
// RPCHandle Implementation

RPCHandle::RPCHandle(ShibSockName shar, u_long program, u_long version)
{
  m_priv = new RPCHandleInternal();

  m_priv->m_shar = shar;
  m_priv->m_program = program;
  m_priv->m_version = version;

  m_priv->log->info("New RPCHandle created: %p", m_priv);
}

RPCHandle::~RPCHandle()
{
  m_priv->log->info("Destroying RPC Handle: %p", m_priv);
  if (m_priv->m_clnt) {
    disconnect();
  }
  delete m_priv;
}

CLIENT * RPCHandle::connect(void)
{
  saml::NDC ndc("connect");

  m_priv->mutex->lock();

  if (m_priv->m_clnt) {
    m_priv->log->debug ("just returning: %p -> %p", m_priv, m_priv->m_clnt);
    return m_priv->m_clnt;
  }

#ifdef WIN32
  m_priv->log->info ("trying to connect to SHAR at %u.",m_priv->m_shar);
#else
  m_priv->log->info ("trying to connect to SHAR at %s.",m_priv->m_shar);
#endif

  ShibSocket sock;

  if (shib_sock_create (&sock) != 0) {
    m_priv->log->error ("Cannot create socket");
    throw new ShibTargetException (SHIBRPC_UNKNOWN_ERROR, "Cannot create socket");
  }

  bool connected = false;
  int num_tries = 3;

  for (int i = num_tries-1; i >= 0; i--) {
    if (shib_sock_connect (sock, m_priv->m_shar) == 0) {
      connected = true;
      break;
    }

    m_priv->log->warn ("Cannot connect %p to SHAR... %s", m_priv,
			(i > 0 ? "retrying" : ""));

    if (i)
#ifdef WIN32
      Sleep(2000*(num_tries-i));
#else
      sleep (2*(num_tries-i));
#endif
  }

  if (!connected) {
    m_priv->log->crit ("SHAR Unavailable..  Failing.");
#ifdef WIN32
    closesocket(sock);
#else
    close (sock);
#endif
    m_priv->mutex->unlock();
    throw new ShibTargetException (SHIBRPC_UNKNOWN_ERROR, "Cannot connect to SHAR");
  }

  CLIENT *clnt = shibrpc_client_create (sock, m_priv->m_program, m_priv->m_version);
  if (!clnt) {
    const char * rpcerror = clnt_spcreateerror ("RPCHandle::connect");
    m_priv->log->error ("RPC failed for %p: %s", m_priv, rpcerror);
#ifdef WIN32
    closesocket(sock);
#else
    close (sock);
#endif
    m_priv->mutex->unlock();
    throw new ShibTargetException (SHIBRPC_UNKNOWN_ERROR, rpcerror);
  }

  // Set the RPC timeout to a fairly high value...
  struct timeval tv;
  tv.tv_sec = 600;		/* change timeout to 10 minutes */
  tv.tv_usec = 0;		/* this should always be set  */
  clnt_control(clnt, CLSET_TIMEOUT, (char*)&tv);

  m_priv->m_clnt = clnt;
  m_priv->m_sock = sock;

  m_priv->log->debug ("success: %p -> %p", m_priv, m_priv->m_clnt);
  return m_priv->m_clnt;
}

void RPCHandle::release(void)
{
  m_priv->mutex->unlock();
}

void RPCHandle::disconnect(void)
{
  m_priv->log->info ("disconnect");
  Lock lock(m_priv->mutex);

  if (m_priv->m_clnt) {
    m_priv->log->debug ("destroying: %p -> %p", m_priv, m_priv->m_clnt);
    clnt_destroy (m_priv->m_clnt);
#ifdef WIN32
    closesocket(m_priv->m_sock);
#else
    close (m_priv->m_sock);
#endif
    m_priv->m_clnt = NULL;
  }
}
