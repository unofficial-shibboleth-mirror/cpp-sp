/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file shibsp/TransactionLog.h
 * 
 * Formatted event record logging.
 */

#if !defined (__shibsp_txlog_h__) && !defined(SHIBSP_LITE)
#define __shibsp_txlog_h__

#include <shibsp/base.h>
#include <xmltooling/logging.h>
#include <xmltooling/Lockable.h>
#include <xmltooling/io/GenericRequest.h>

#include <map>
#include <vector>
#include <iostream>
#include <boost/scoped_ptr.hpp>

namespace xmltooling {
    class XMLTOOL_API Mutex;
};

namespace opensaml {
    namespace saml1 {
        class SAML_API AuthenticationStatement;
    };

    namespace saml1p {
        class SAML_API Response;
    };

    namespace saml2 {
        class SAML_API AuthnStatement;
        class SAML_API NameID;
    };

    namespace saml2p {
        class SAML_API AuthnRequest;
        class SAML_API LogoutRequest;
        class SAML_API LogoutResponse;
        class SAML_API StatusResponseType;
    };

    namespace saml2md {
        class SAML_API EntityDescriptor;
    };
};

namespace shibsp {
    class SHIBSP_API Application;
    class SHIBSP_API Attribute;
    class SHIBSP_API Session;

    /**
     * Interface to a synchronized event/audit logging object.
     * 
     * <p>For backward compatibility, we expose a logging object directly, but
     * new applications should rely on the Event callback API.
     */
    class SHIBSP_API TransactionLog : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(TransactionLog);
    public:
        /**
         * Constructor.
         *
         * @param fmt       formatting string for events
         * @param absent    string to output when a field is empty
         */
        TransactionLog(const char* fmt=nullptr, const char* absent=nullptr);

        virtual ~TransactionLog();
        
        xmltooling::Lockable* lock();
        void unlock();

        /** @deprecated Logging object. */
        xmltooling::logging::Category& log;

        /**
         * Callback interface that outputs an event record to a stream using formatting tokens.
         */
        class SHIBSP_API Event {
            MAKE_NONCOPYABLE(Event);
        protected:
            /** Function that handles a formatting token. */
            typedef bool (*handler_fn)(const Event& e, std::ostream&);

            /** Map of tokens to handlers. */
            std::map<std::string, handler_fn> m_handlers;

            /**
             * Constructor.
             */
            Event();

        public:
            virtual ~Event();

            /**
             * Returns a type string to be used for the log category in the event log.
             *
             * @return  type or category for the event
             */
            virtual const char* getType() const=0;

            /** Exception */
            const std::exception* m_exception;

            /** Request object associated with event. */
            const xmltooling::GenericRequest* m_request;

            /** Application object associated with event. */
            const Application* m_app;

            /** Session identifier. */
            const char* m_sessionID;

            /** Peer entity associated with event. */
            const opensaml::saml2md::EntityDescriptor* m_peer;

            /** Protocol associated with event. */
            const char* m_protocol;

            /** Protocol binding associated with event. */
            const char* m_binding;

            /** SAML 2.0 NameID. */
            const opensaml::saml2::NameID* m_nameID;

            /**
             * Outputs an event record to a stream based on the defined formatting string.
             *
             * @param out       stream to use
             * @param field     field to output
             * @param absent    string to output if the field is empty
             * @return  true iff the field was recognized and substituted
             */
            virtual bool write(std::ostream& out, const char* field, const char* absent) const;
        };

        /**
         * Write a formatted event record to the log.
         * <p>This method is internally synchronized and the caller does <strong>NOT</strong>
         * need to explicitly lock and unlock the object.
         *
         * @param e event to log
         */
        virtual void write(const Event& e);

    private:
        boost::scoped_ptr<xmltooling::Mutex> m_lock;
        std::string m_absent;
        std::vector<std::string> m_formatting;
    };

    class SHIBSP_API LoginEvent : public TransactionLog::Event
    {
    public:
        /**
         * Constructor.
         */
        LoginEvent();

        virtual ~LoginEvent();

        const char* getType() const;

        /** SAML 2.0 AuthnStatement. */
        const opensaml::saml2::AuthnStatement* m_saml2AuthnStatement;

        /** SAML 2.0 Response. */
        const opensaml::saml2p::StatusResponseType* m_saml2Response;

        /** SAML 1.x AuthnStatement. */
        const opensaml::saml1::AuthenticationStatement* m_saml1AuthnStatement;

        /** SAML 1.x Response. */
        const opensaml::saml1p::Response* m_saml1Response;

        /** Attributes associated with event. */
        const std::vector<Attribute*>* m_attributes;
    };

    class SHIBSP_API LogoutEvent : public TransactionLog::Event
    {
    public:
        /**
         * Constructor.
         */
        LogoutEvent();

        virtual ~LogoutEvent();

        const char* getType() const;

        /** Result of logout (local, global, partial). */
        enum logout_type_t {
            LOGOUT_EVENT_UNKNOWN,
            LOGOUT_EVENT_INVALID,
            LOGOUT_EVENT_LOCAL,
            LOGOUT_EVENT_GLOBAL,
            LOGOUT_EVENT_PARTIAL
        } m_logoutType;

        /** SAML 2.0 Request. */
        const opensaml::saml2p::LogoutRequest* m_saml2Request;

        /** SAML 2.0 Response. */
        const opensaml::saml2p::LogoutResponse* m_saml2Response;

        /** Primary session associated with event. */
        const Session* m_session;

        /** All sessions associated with event. */
        std::vector<std::string> m_sessions;
    };

    class SHIBSP_API AuthnRequestEvent : public TransactionLog::Event
    {
    public:
        /**
         * Constructor.
         */
        AuthnRequestEvent();

        virtual ~AuthnRequestEvent();

        const char* getType() const;

        /** SAML 2.0 Request. */
        const opensaml::saml2p::AuthnRequest* m_saml2Request;
    };

    /**
     * Registers Event classes into the runtime.
     */
    void SHIBSP_API registerEvents();

    /** Login event. */
    #define LOGIN_EVENT         "Login"

    /** Logout event. */
    #define LOGOUT_EVENT        "Logout"

    /** AuthnRequest event. */
    #define AUTHNREQUEST_EVENT  "AuthnRequest"
};

#endif /* __shibsp_txlog_h__ */
