/*
 * shib-rpchandle.cpp -- the RPC Handle abstraction
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"
#include "shib-threads.h"

#include <log4cpp/Category.hh>

#include <stdexcept>

using namespace std;
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

  m_priv->mutex->lock();

  if (m_priv->m_clnt)
    return m_priv->m_clnt;

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

    m_priv->log->warn ("Cannot connect to SHAR... %s",
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
    m_priv->log->error ("RPC failed: %s", rpcerror);
#ifdef WIN32
    closesocket(sock);
#else
    close (sock);
#endif
    m_priv->mutex->unlock();
    throw new ShibTargetException (SHIBRPC_UNKNOWN_ERROR, rpcerror);
  }

  m_priv->m_clnt = clnt;
  m_priv->m_sock = sock;

  m_priv->log->debug ("success");
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
    clnt_destroy (m_priv->m_clnt);
#ifdef WIN32
    closesocket(m_priv->m_sock);
#else
    close (m_priv->m_sock);
#endif
    m_priv->m_clnt = NULL;
  }
}
