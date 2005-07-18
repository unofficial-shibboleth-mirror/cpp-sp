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

#include <saml/saml.h>  // need this to "prime" the xmlsec-constrained windows.h declaration
#include <shib-target/shibrpc.h>
#include "internal.h"

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
        IListener::ShibSocket m_sock;
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
    
    // Local-wrapper for an ISessionCacheEntry
    class EntryWrapper : public virtual ISessionCacheEntry
    {
    public:
        EntryWrapper(shibrpc_get_session_ret_2& ret, Category& log);
        ~EntryWrapper() { delete statement; delete pre_response; delete post_response; }
        void lock() {}
        void unlock() { delete this; }
        virtual bool isValid(time_t lifetime, time_t timeout) const { return true; }
        virtual const char* getClientAddress() const { return NULL; }
        virtual ShibProfile getProfile() const { return profile; }
        virtual const char* getProviderId() const { return provider_id.c_str(); }
        virtual const saml::SAMLAuthenticationStatement* getAuthnStatement() const { return statement; }
        virtual CachedResponse getResponse() { return CachedResponse(pre_response,post_response); }
    
    private:
        string provider_id;
        ShibProfile profile;
        SAMLAuthenticationStatement* statement;
        SAMLResponse* pre_response;
        SAMLResponse* post_response;
    };
}


RPCListener::RPCListener(const DOMElement* e) : log(&Category::getInstance(SHIBT_LOGCAT".Listener"))
{
    m_rpcpool=new RPCHandlePool(*log,this);
}

RPCListener::~RPCListener()
{
    delete m_rpcpool;
}

void RPCListener::sessionNew(
    const IApplication* application,
    int supported_profiles,
    const char* recipient,
    const char* packet,
    const char* ip,
    string& target,
    string& cookie,
    string& provider_id
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionNew");
#endif

    if (!packet || !*packet) {
        log->error("missing profile response");
        throw FatalProfileException("Profile response missing.");
    }

    if (!ip || !*ip) {
        log->error("missing client address");
        throw FatalProfileException("Invalid client address.");
    }
  
    if (supported_profiles <= 0) {
        log->error("no profile support indicated");
        throw FatalProfileException("No profile support indicated.");
    }
  
    shibrpc_new_session_args_2 arg;
    arg.recipient = (char*)recipient;
    arg.application_id = (char*)application->getId();
    arg.packet = (char*)packet;
    arg.client_addr = (char*)ip;
    arg.supported_profiles = supported_profiles;

    log->info("create session for user at (%s) for application (%s)", ip, arg.application_id);

    shibrpc_new_session_ret_2 ret;
    memset(&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT* clnt;
    RPC rpc(*m_rpcpool);
    do {
        clnt = rpc->connect(this);
        clnt_stat status = shibrpc_new_session_2(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and retry
            log->error("RPC Failure: (CLIENT: %p) (%d): %s", clnt, status, clnt_spcreateerror("shibrpc_new_session_2"));
            rpc->disconnect(this);
            if (retry)
                retry--;
            else
                throw ListenerException("Failure passing session setup information to listener.");
        }
        else {
            // SUCCESS.  Pool and continue
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log->debug("RPC completed with exception: %s", ret.status);
    else
        log->debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log->error("caught SAML Exception while building the SAMLException: %s", e.what());
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while creating your session.");
        }
#ifndef _DEBUG
        catch (...) {
            log->error("caught unknown exception building SAMLException");
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#endif
    }
    else {
        log->debug("new session from IdP (%s) with key (%s)", ret.provider_id, ret.cookie);
        cookie = ret.cookie;
        provider_id = ret.provider_id;
        if (ret.target)
            target = ret.target;
    }

    clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

EntryWrapper::EntryWrapper(shibrpc_get_session_ret_2& ret, Category& log)
{
    profile = static_cast<ShibProfile>(ret.profile);
    int minor = (profile==SAML10_POST || profile==SAML10_ARTIFACT) ? 0 : 1;

    provider_id = ret.provider_id;

    istringstream authstream(ret.auth_statement);
    log.debugStream() << "trying to decode authentication statement: "
        << ((ret.auth_statement && *ret.auth_statement) ? ret.auth_statement : "(none)") << CategoryStream::ENDLINE;
    auto_ptr<SAMLAuthenticationStatement> s(
    	(ret.auth_statement && *ret.auth_statement) ? new SAMLAuthenticationStatement(authstream) : NULL
    	);

    istringstream prestream(ret.attr_response_pre);
    log.debugStream() << "trying to decode unfiltered attribute response: "
        << ((ret.attr_response_pre && *ret.attr_response_pre) ? ret.attr_response_pre : "(none)") << CategoryStream::ENDLINE;
    auto_ptr<SAMLResponse> pre(
    	(ret.attr_response_pre && *ret.attr_response_pre) ? new SAMLResponse(prestream,minor) : NULL
    	);

    istringstream poststream(ret.attr_response_post);
    log.debugStream() << "trying to decode filtered attribute response: "
        << ((ret.attr_response_post && *ret.attr_response_post) ? ret.attr_response_post : "(none)") << CategoryStream::ENDLINE;
    auto_ptr<SAMLResponse> post(
    	(ret.attr_response_post && *ret.attr_response_post) ? new SAMLResponse(poststream,minor) : NULL
    	);

    statement=s.release();
    pre_response = pre.release();
    post_response = post.release();
}

void RPCListener::sessionGet(
    const IApplication* application,
    const char* cookie,
    const char* ip,
    ISessionCacheEntry** pentry
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionGet");
#endif

    if (!cookie || !*cookie) {
        log->error("no session key provided");
        throw InvalidSessionException("No session key was provided.");
    }
    else if (strchr(cookie,'=')) {
        log->error("cookie value not extracted successfully, probably overlapping cookies across domains");
        throw InvalidSessionException("The session key wasn't extracted successfully from the browser cookie.");
    }

    if (!ip || !*ip) {
        log->error("invalid client Address");
        throw FatalProfileException("Invalid client address.");
    }

    log->debug("getting session for client at (%s)", ip);
    log->debug("session cookie (%s)", cookie);

    shibrpc_get_session_args_2 arg;
    arg.cookie = (char*)cookie;
    arg.client_addr = (char*)ip;
    arg.application_id = (char*)application->getId();

    shibrpc_get_session_ret_2 ret;
    memset (&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT *clnt;
    RPC rpc(*m_rpcpool);
    do {
        clnt = rpc->connect(this);
        clnt_stat status = shibrpc_get_session_2(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and try again...
            log->error("RPC Failure: (CLIENT: %p) (%d) %s", clnt, status, clnt_spcreateerror("shibrpc_get_session_2"));
            rpc->disconnect(this);
            if (retry)
                retry--;
            else
                throw ListenerException("Failure requesting session information from listener.");
        }
        else {
            // SUCCESS
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log->debug("RPC completed with exception: %s", ret.status);
    else
        log->debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log->error("caught SAML Exception while building the SAMLException: %s", e.what());
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while accessing your session.");
        }
        catch (...) {
            log->error("caught unknown exception building SAMLException");
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
    }
    else {
        try {
            *pentry=new EntryWrapper(ret,*log);
        }
        catch (SAMLException& e) {
            log->error("caught SAML exception while reconstituting session objects: %s", e.what());
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#ifndef _DEBUG
        catch (...) {
            log->error("caught unknown exception while reconstituting session objects");
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#endif
    }

    clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

void RPCListener::sessionEnd(
    const IApplication* application,
    const char* cookie
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionEnd");
#endif

    if (!cookie || !*cookie) {
        log->error("no session key provided");
        throw InvalidSessionException("No session key was provided.");
    }
    else if (strchr(cookie,'=')) {
        log->error("cookie value not extracted successfully, probably overlapping cookies across domains");
        throw InvalidSessionException("The session key wasn't extracted successfully from the browser cookie.");
    }

    log->debug("ending session with cookie (%s)", cookie);

    shibrpc_end_session_args_2 arg;
    arg.cookie = (char*)cookie;

    shibrpc_end_session_ret_2 ret;
    memset (&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT *clnt;
    RPC rpc(*m_rpcpool);
    do {
        clnt = rpc->connect(this);
        clnt_stat status = shibrpc_end_session_2(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and try again...
            log->error("RPC Failure: (CLIENT: %p) (%d) %s", clnt, status, clnt_spcreateerror("shibrpc_end_session_2"));
            rpc->disconnect(this);
            if (retry)
                retry--;
            else
                throw ListenerException("Failure ending session through listener.");
        }
        else {
            // SUCCESS
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log->debug("RPC completed with exception: %s", ret.status);
    else
        log->debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log->error("caught SAML Exception while building the SAMLException: %s", e.what());
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while accessing your session.");
        }
        catch (...) {
            log->error("caught unknown exception building SAMLException");
            log->error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
    }

    clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

void RPCListener::ping(int& i) const
{
#ifdef _DEBUG
    saml::NDC ndc("ping");
#endif

    int result=-1;
    log->debug("pinging with (%d)", i);

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT *clnt;
    RPC rpc(*m_rpcpool);
    do {
        clnt = rpc->connect(this);
        clnt_stat status = shibrpc_ping_2(&i, &result, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and try again...
            log->error("RPC Failure: (CLIENT: %p) (%d) %s", clnt, status, clnt_spcreateerror("shibrpc_end_session_2"));
            rpc->disconnect(this);
            if (retry)
                retry--;
            else
                throw ListenerException("Failure pinging listener.");
        }
        else {
            // SUCCESS
            retry = -1;
        }
    } while (retry>=0);

    log->debug("RPC completed successfully");
    i=result;
    rpc.pool();
}

RPCHandle::RPCHandle(Category& log) : m_clnt(NULL), m_sock((IListener::ShibSocket)0), m_log(log)
{
    m_log.debug("New RPCHandle created: %p", this);
}

RPCHandle::~RPCHandle()
{
    m_log.debug("Destroying RPC Handle: %p", this);
    disconnect();
}

void RPCHandle::disconnect(const RPCListener* listener)
{
    if (m_clnt) {
        clnt_destroy(m_clnt);
        m_clnt=NULL;
        if (listener) {
            listener->close(m_sock);
            m_sock=(IListener::ShibSocket)0;
        }
        else {
#ifdef WIN32
            ::closesocket(m_sock);
#else
            ::close(m_sock);
#endif
            m_sock=(IListener::ShibSocket)0;
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

    IListener::ShibSocket sock;
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

    CLIENT* clnt = (CLIENT*)listener->getClientHandle(sock, SHIBRPC_PROG, SHIBRPC_VERS_2);
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
