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
 * RPCListener.cpp -- Handles marshalling and connection mgmt for ONC-remoted IListeners
 *
 * Scott Cantor
 * 5/1/05
 *
 */

#include "RPCListener.h"

// Deal with inadequate Sun RPC libraries

#if !HAVE_DECL_SVCFD_CREATE
  extern "C" SVCXPRT* svcfd_create(int, u_int, u_int);
#endif

#ifndef HAVE_WORKING_SVC_DESTROY
struct tcp_conn {  /* kept in xprt->xp_p1 */
    enum xprt_stat strm_stat;
    u_long x_id;
    XDR xdrs;
    char verf_body[MAX_AUTH_BYTES];
};
#endif

extern "C" void shibrpc_prog_3(struct svc_req* rqstp, register SVCXPRT* transp);

#include <errno.h>
#include <sstream>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace shibtarget {
    // Wraps the actual RPC connection
    class RPCHandle
    {
    public:
        RPCHandle(Category& log);
        ~RPCHandle();

        CLIENT* connect(const RPCListener* listener);         // connects and returns the CLIENT handle
        void disconnect(const RPCListener* listener=NULL);    // disconnects, should not return disconnected handles to pool!

    private:
        Category& m_log;
        CLIENT* m_clnt;
        RPCListener::ShibSocket m_sock;
    };
  
    // Manages the pool of connections
    class RPCHandlePool
    {
    public:
        RPCHandlePool(Category& log, const RPCListener* listener)
            : m_log(log), m_listener(listener), m_lock(shibboleth::Mutex::create()) {}
        ~RPCHandlePool();
        RPCHandle* get();
        void put(RPCHandle*);
  
    private:
        const RPCListener* m_listener;
        Category& m_log;
        auto_ptr<Mutex> m_lock;
        stack<RPCHandle*> m_pool;
    };
  
    // Cleans up after use
    class RPC
    {
    public:
        RPC(RPCHandlePool& pool);
        ~RPC() {delete m_handle;}
        RPCHandle* operator->() {return m_handle;}
        void pool() {if (m_handle) m_pool.put(m_handle); m_handle=NULL;}
    
    private:
        RPCHandle* m_handle;
        RPCHandlePool& m_pool;
    };
    
    // Worker threads in server
    class ServerThread {
    public:
        ServerThread(RPCListener::ShibSocket& s, RPCListener* listener);
        ~ServerThread();
        void run();

    private:
        bool svc_create();
        RPCListener::ShibSocket m_sock;
        Thread* m_child;
        RPCListener* m_listener;
    };
}


RPCListener::RPCListener(const DOMElement* e) : log(&Category::getInstance(SHIBT_LOGCAT".Listener")),
    m_shutdown(NULL), m_child_lock(NULL), m_child_wait(NULL), m_rpcpool(NULL), m_socket((ShibSocket)0)
{
    // Are we a client?
    if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::InProcess)) {
        m_rpcpool=new RPCHandlePool(*log,this);
    }
    // Are we a server?
    if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::OutOfProcess)) {
        m_child_lock = Mutex::create();
        m_child_wait = CondWait::create();
    }
}

RPCListener::~RPCListener()
{
    delete m_rpcpool;
    delete m_child_wait;
    delete m_child_lock;
}

bool RPCListener::run(bool* shutdown)
{
#ifdef _DEBUG
    saml::NDC ndc("run");
#endif

    // Save flag to monitor for shutdown request.
    m_shutdown=shutdown;

    if (!create(m_socket)) {
        log->crit("failed to create socket");
        return false;
    }
    if (!bind(m_socket,true)) {
        this->close(m_socket);
        log->crit("failed to bind to socket.");
        return false;
    }

    while (!*m_shutdown) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_socket, &readfds);
        struct timeval tv = { 0, 0 };
        tv.tv_sec = 5;
    
        switch (select(m_socket + 1, &readfds, 0, 0, &tv)) {
#ifdef WIN32
            case SOCKET_ERROR:
#else
            case -1:
#endif
                if (errno == EINTR) continue;
                log_error();
                log->error("select() on main listener socket failed");
                return false;
        
            case 0:
                continue;
        
            default:
            {
                // Accept the connection.
                RPCListener::ShibSocket newsock;
                if (!accept(m_socket, newsock))
                    log->crit("failed to accept incoming socket connection");

                // We throw away the result because the children manage themselves...
                try {
                    new ServerThread(newsock,this);
                }
                catch (...) {
                    log->crit("error starting new server thread to service incoming request");
                }
            }
        }
    }
    log->info("listener service shutting down");

    // Wait for all children to exit.
    m_child_lock->lock();
    while (!m_children.empty())
        m_child_wait->wait(m_child_lock);
    m_child_lock->unlock();

    this->close(m_socket);
    m_socket=(ShibSocket)0;
    return true;
}

DDF RPCListener::send(const DDF& in)
{
#ifdef _DEBUG
    saml::NDC ndc("send");
#endif

    // Serialize data for transmission.
    ostringstream os;
    os << in;
    shibrpc_args_3 arg;
    string ostr(os.str());
    arg.xml = const_cast<char*>(ostr.c_str());

    log->debug("sending message: %s", in.name());

    shibrpc_ret_3 ret;
    memset(&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT* clnt;
    RPC rpc(*m_rpcpool);
    do {
        clnt = rpc->connect(this);
        clnt_stat status = shibrpc_call_3(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and retry
            log->error("RPC Failure: (CLIENT: %p) (%d): %s", clnt, status, clnt_spcreateerror("shibrpc_call_3"));
            rpc->disconnect(this);
            if (retry)
                retry--;
            else
                throw ListenerException("Failure sending remoted message ($1).",params(1,in.name()));
        }
        else {
            // SUCCESS.  Pool and continue
            retry = -1;
        }
    } while (retry>=0);

    log->debug("call completed, unmarshalling response message");

    // Deserialize data.
    DDF out;
    try {
        istringstream is(ret.xml);
        is >> out;
        clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_ret_3, (caddr_t)&ret);
        rpc.pool();
    }
    catch (...) {
        log->error("caught exception while unmarshalling response message");
        clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_ret_3, (caddr_t)&ret);
        rpc.pool();
        throw;
    }
    
    // Check for exception to unmarshall and throw, otherwise return.
    if (out.isstring() && out.name() && !strcmp(out.name(),"exception")) {
        // Reconstitute exception object.
        DDFJanitor jout(out);
        SAMLException* except=NULL;
        try { 
            istringstream es(out.string());
            except=SAMLException::getInstance(es);
        }
        catch (SAMLException& e) {
            log->error("caught SAML Exception while building the SAMLException: %s", e.what());
            log->error("XML was: %s", out.string());
            throw ListenerException("Remote call failed with an unparsable exception.");
        }
#ifndef _DEBUG
        catch (...) {
            log->error("caught unknown exception building SAMLException");
            log->error("XML was: %s", out.string());
            throw;
        }
#endif
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }

    return out;
}

bool RPCListener::log_error() const
{
#ifdef WIN32
    int rc=WSAGetLastError();
#else
    int rc=errno;
#endif
#ifdef HAVE_STRERROR_R
    char buf[256];
    memset(buf,0,sizeof(buf));
    strerror_r(rc,buf,sizeof(buf));
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#else
    const char* buf=strerror(rc);
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#endif
    return false;
}

RPCHandle::RPCHandle(Category& log) : m_clnt(NULL), m_sock((RPCListener::ShibSocket)0), m_log(log)
{
    m_log.debug("new RPCHandle created: %p", this);
}

RPCHandle::~RPCHandle()
{
    m_log.debug("destroying RPC Handle: %p", this);
    disconnect();
}

void RPCHandle::disconnect(const RPCListener* listener)
{
    if (m_clnt) {
        clnt_destroy(m_clnt);
        m_clnt=NULL;
        if (listener) {
            listener->close(m_sock);
            m_sock=(RPCListener::ShibSocket)0;
        }
        else {
#ifdef WIN32
            ::closesocket(m_sock);
#else
            ::close(m_sock);
#endif
            m_sock=(RPCListener::ShibSocket)0;
        }
    }
}

CLIENT* RPCHandle::connect(const RPCListener* listener)
{
#ifdef _DEBUG
    saml::NDC ndc("connect");
#endif
    if (m_clnt) {
        m_log.debug("returning existing connection: %p -> %p", this, m_clnt);
        return m_clnt;
    }

    m_log.debug("trying to connect to socket");

    RPCListener::ShibSocket sock;
    if (!listener->create(sock)) {
        m_log.error("cannot create socket");
        throw ListenerException("Cannot create socket");
    }

    bool connected = false;
    int num_tries = 3;

    for (int i = num_tries-1; i >= 0; i--) {
        if (listener->connect(sock)) {
            connected = true;
            break;
        }
    
        m_log.warn("cannot connect %p to socket...%s", this, (i > 0 ? "retrying" : ""));

        if (i) {
#ifdef WIN32
            Sleep(2000*(num_tries-i));
#else
            sleep(2*(num_tries-i));
#endif
        }
    }

    if (!connected) {
        m_log.crit("socket server unavailable, failing");
        listener->close(sock);
        throw ListenerException("Cannot connect to listener process, a site adminstrator should be notified.");
    }

    CLIENT* clnt = (CLIENT*)listener->getClientHandle(sock, SHIBRPC_PROG, SHIBRPC_VERS_3);
    if (!clnt) {
        const char* rpcerror = clnt_spcreateerror("RPCHandle::connect");
        m_log.crit("RPC failed for %p: %s", this, rpcerror);
        listener->close(sock);
        throw ListenerException(rpcerror);
    }

    // Set the RPC timeout to a fairly high value...
    struct timeval tv;
    tv.tv_sec = 300;    /* change timeout to 5 minutes */
    tv.tv_usec = 0;     /* this should always be set  */
    clnt_control(clnt, CLSET_TIMEOUT, (char*)&tv);

    m_clnt = clnt;
    m_sock = sock;

    m_log.debug("success: %p -> %p", this, m_clnt);
    return m_clnt;
}

RPCHandlePool::~RPCHandlePool()
{
    while (!m_pool.empty()) {
        delete m_pool.top();
        m_pool.pop();
    }
}

RPCHandle* RPCHandlePool::get()
{
    m_lock->lock();
    if (m_pool.empty()) {
        m_lock->unlock();
        return new RPCHandle(m_log);
    }
    RPCHandle* ret=m_pool.top();
    m_pool.pop();
    m_lock->unlock();
    return ret;
}

void RPCHandlePool::put(RPCHandle* handle)
{
    m_lock->lock();
    m_pool.push(handle);
    m_lock->unlock();
}

RPC::RPC(RPCHandlePool& pool) : m_pool(pool)
{
    m_handle=m_pool.get();
}

// actual function run in listener on server threads
void* server_thread_fn(void* arg)
{
    ServerThread* child = (ServerThread*)arg;

    // First, let's block all signals
    Thread::mask_all_signals();

    // Run the child until it exits.
    child->run();

    // Now we can clean up and exit the thread.
    delete child;
    return NULL;
}

ServerThread::ServerThread(RPCListener::ShibSocket& s, RPCListener* listener)
    : m_sock(s), m_child(NULL), m_listener(listener)
{
    // Create the child thread
    m_child = Thread::create(server_thread_fn, (void*)this);
    m_child->detach();
}

ServerThread::~ServerThread()
{
    // Then lock the children map, remove this socket/thread, signal waiters, and return
    m_listener->m_child_lock->lock();
    m_listener->m_children.erase(m_sock);
    m_listener->m_child_lock->unlock();
    m_listener->m_child_wait->signal();
  
    delete m_child;
}

void ServerThread::run()
{
    // Before starting up, make sure we fully "own" this socket.
    m_listener->m_child_lock->lock();
    while (m_listener->m_children.find(m_sock)!=m_listener->m_children.end())
        m_listener->m_child_wait->wait(m_listener->m_child_lock);
    m_listener->m_children[m_sock] = m_child;
    m_listener->m_child_lock->unlock();
    
    if (!svc_create())
        return;

    fd_set readfds;
    struct timeval tv = { 0, 0 };

    while(!*(m_listener->m_shutdown) && FD_ISSET(m_sock, &svc_fdset)) {
        FD_ZERO(&readfds);
        FD_SET(m_sock, &readfds);
        tv.tv_sec = 1;

        switch (select(m_sock+1, &readfds, 0, 0, &tv)) {
#ifdef WIN32
        case SOCKET_ERROR:
#else
        case -1:
#endif
            if (errno == EINTR) continue;
            m_listener->log_error();
            m_listener->log->error("select() on incoming request socket (%u) returned error", m_sock);
            return;

        case 0:
            break;

        default:
            svc_getreqset(&readfds);
        }
    }
}

bool ServerThread::svc_create()
{
    /* Wrap an RPC Service around the new connection socket. */
    SVCXPRT* transp = svcfd_create(m_sock, 0, 0);
    if (!transp) {
#ifdef _DEBUG
        NDC ndc("svc_create");
#endif
        m_listener->log->error("failed to wrap RPC service around socket");
        return false;
    }

    /* Register the SHIBRPC RPC Program */
    if (!svc_register (transp, SHIBRPC_PROG, SHIBRPC_VERS_3, shibrpc_prog_3, 0)) {
#ifdef HAVE_WORKING_SVC_DESTROY
        svc_destroy(transp);
#else
        /* we have to inline svc_destroy because we can't pass in the xprt variable */
        struct tcp_conn *cd = (struct tcp_conn *)transp->xp_p1;
        xprt_unregister(transp);
        close(transp->xp_sock);
        if (transp->xp_port != 0) {
            /* a rendezvouser socket */
            transp->xp_port = 0;
        }
        else {
            /* an actual connection socket */
            XDR_DESTROY(&(cd->xdrs));
        }
        mem_free((caddr_t)cd, sizeof(struct tcp_conn));
        mem_free((caddr_t)transp, sizeof(SVCXPRT));
#endif
#ifdef _DEBUG
        NDC ndc("svc_create");
#endif
        m_listener->log->error("failed to register RPC program");
        return false;
    }

    return true;
}

static string get_threadid()
{
  static u_long counter = 0;
  ostringstream buf;
  buf << "[" << counter++ << "]";
  return buf.str();
}

extern "C" bool_t shibrpc_call_3_svc(
    shibrpc_args_3 *argp,
    shibrpc_ret_3 *result,
    struct svc_req *rqstp
    )
{
    string ctx=get_threadid();
    saml::NDC ndc(ctx);
    Category& log = Category::getInstance("shibd.Listener");

    if (!argp || !result) {
        log.error("RPC Argument Error");
        return FALSE;
    }

    memset(result, 0, sizeof (*result));

    DDF out;
    DDFJanitor jout(out);

    try {
        // Lock the configuration.
        IConfig* conf=ShibTargetConfig::getConfig().getINI();
        Locker locker(conf);

        // Get listener interface.
        IListener* listener=conf->getListener();
        if (!listener)
            throw ListenerException("No listener implementation found to process incoming message.");
        
        // Unmarshal the message.
        DDF in;
        DDFJanitor jin(in);
        istringstream is(argp->xml);
        is >> in;

        // Dispatch the message.
        out=listener->receive(in);
    }
    catch (SAMLException &e) {
        log.error("error processing incoming message: %s", e.what());
        ostringstream os;
        os << e;
        out=DDF("exception").string(os.str().c_str());
    }
#ifndef _DEBUG
    catch (...) {
        log.error("unexpected error processing incoming message");
        ListenerException ex("An unexpected error occurred while processing an incoming message.");
        ostringstream os;
        os << ex;
        out=DDF("exception").string(os.str().c_str());
    }
#endif
    
    // Return whatever's available.
    ostringstream xmlout;
    xmlout << out;
    result->xml=strdup(xmlout.str().c_str());
    return TRUE;
}

extern "C" int
shibrpc_prog_3_freeresult (SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
	xdr_free (xdr_result, result);

	/*
	 * Insert additional freeing code here, if needed
	 */

	return 1;
}
