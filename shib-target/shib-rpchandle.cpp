/*
 * shib-rpchandle.cpp -- the RPC Handle abstraction
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>

#include "shib-target.h"

#include <log4cpp/Category.hh>

#include <stdexcept>

using namespace std;
using namespace shibtarget;


class shibtarget::RPCHandleInternal
{
public:
  RPCHandleInternal();
  ~RPCHandleInternal();

  CLIENT *	m_clnt;
  ShibSocket	m_sock;

  ShibSockName m_shar;
  u_long	m_program;
  u_long	m_version;

  log4cpp::Category* log;
};

RPCHandleInternal::RPCHandleInternal()
{
  string ctx = "shibtarget.RPCHandle";
  log = &(log4cpp::Category::getInstance(ctx));
  m_clnt = NULL;
}

RPCHandleInternal::~RPCHandleInternal() {}

//*************************************************************************
// RPCHandle Implementation

RPCHandle::RPCHandle(ShibSockName shar, u_long program, u_long version)
{
  m_priv = new RPCHandleInternal();

  m_priv->m_shar = shar;
  m_priv->m_program = program;
  m_priv->m_version = version;

  m_priv->log->info("New RPCHandle created");
}

RPCHandle::~RPCHandle()
{
  m_priv->log->info("Destroying RPC Handle");
  if (m_priv->m_clnt) {
    disconnect();
  }
  delete m_priv;
}

CLIENT * RPCHandle::connect(void)
{
  saml::NDC ndc("connect");

  if (m_priv->m_clnt)
    return m_priv->m_clnt;

  m_priv->log->info ("trying to connect to SHAR at %s.",
#ifdef WIN32
#error "Not defined yet"
#else
		     m_priv->m_shar
#endif
		     );

  ShibSocket sock;

  if (shib_sock_create (&sock) != 0) {
    m_priv->log->error ("Cannot create socket");
    throw runtime_error ("Cannot create socket");
  }

  // XXX: Loop until we connect?
  if (shib_sock_connect (sock, m_priv->m_shar) != 0) {
    m_priv->log->warn ("Cannot connect to SHAR");
    close (sock);
    throw runtime_error ("Cannot connect to SHAR");
  }

  CLIENT *clnt = shibrpc_client_create (sock, m_priv->m_program, m_priv->m_version);
  if (!clnt) {
    const char * rpcerror = clnt_spcreateerror ("RPCHandle::connect");
    m_priv->log->error ("RPC failed: %s", rpcerror);
    close (sock);
    throw runtime_error (rpcerror);
  }

  m_priv->m_clnt = clnt;
  m_priv->m_sock = sock;

  m_priv->log->debug ("success");
  return m_priv->m_clnt;
}

void RPCHandle::disconnect(void)
{
  m_priv->log->info ("disconnect");
  if (m_priv->m_clnt) {
    clnt_destroy (m_priv->m_clnt);
    close (m_priv->m_sock);
    m_priv->m_clnt = NULL;
  }
}
