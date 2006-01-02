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

/* RPCListener.h - ONC RPC-based Listener implementation

   $Id$
*/

#ifndef __RPCListener_h__
#define __RPCListener_h__

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif

#include <saml/saml.h>  // need this to "prime" the xmlsec-constrained windows.h declaration
#include <shib-target/shibrpc.h>
#include "internal.h"

namespace shibtarget {

    class RPCHandlePool;
    class ServerThread;
    class RPCListener : public virtual IListener
    {
    public:
        RPCListener(const DOMElement* e);
        ~RPCListener();

        DDF send(const DDF& in);
        bool run(bool* shutdown);

        // Implemented by socket-specific subclasses.
#ifdef WIN32
        typedef SOCKET ShibSocket;
#else
        typedef int ShibSocket;
#endif
        virtual bool create(ShibSocket& s) const=0;
        virtual bool connect(ShibSocket& s) const=0;
        virtual bool bind(ShibSocket& s, bool force=false) const=0;
        virtual bool accept(ShibSocket& listener, ShibSocket& s) const=0;
        virtual bool close(ShibSocket& s) const=0;
        virtual CLIENT* getClientHandle(ShibSocket& s, u_long program, u_long version) const=0;

    protected:
        bool log_error() const; // for OS-level errors
        log4cpp::Category* log;
    
    private:
        mutable RPCHandlePool* m_rpcpool;
        bool* m_shutdown;

        // Manage child threads
        friend class ServerThread;
        std::map<ShibSocket,shibboleth::Thread*> m_children;
        shibboleth::Mutex* m_child_lock;
        shibboleth::CondWait* m_child_wait;

        // Primary socket
        ShibSocket m_socket;
    };
}

#endif
