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
 * ChainingSessionInitiator.cpp
 * 
 * Chains together multiple SessionInitiator handlers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/bind.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL ChainingSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        ChainingSessionInitiator(const DOMElement* e, const char* appId, bool deprecationSupport=true);
        virtual ~ChainingSessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        ptr_vector<SessionInitiator> m_handlers;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh _SessionInitiator[] =    UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    class SHIBSP_DLLLOCAL SessionInitiatorNodeFilter : public DOMNodeFilter
    {
    public:
        FilterAction acceptNode(const DOMNode* node) const {
            if (XMLString::equals(node->getLocalName(), _SessionInitiator))
                return FILTER_REJECT;
            return FILTER_ACCEPT;
        }
    };

    static SHIBSP_DLLLOCAL SessionInitiatorNodeFilter g_SINFilter;

    SessionInitiator* SHIBSP_DLLLOCAL ChainingSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p, bool deprecationSupport)
    {
        return new ChainingSessionInitiator(p.first, p.second, deprecationSupport);
    }
};

ChainingSessionInitiator::ChainingSessionInitiator(const DOMElement* e, const char* appId, bool deprecationSupport)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT ".SessionInitiator.Chaining"), &g_SINFilter)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _SessionInitiator) : nullptr;
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (!t.empty()) {
            try {
                auto_ptr<SessionInitiator> np(conf.SessionInitiatorManager.newPlugin(t.c_str(), make_pair(e, appId), deprecationSupport));
                m_handlers.push_back(np.get());
                np.release();
                m_handlers.back().setParent(this);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception processing embedded SessionInitiator element: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _SessionInitiator);
    }

    m_supportedOptions.insert("isPassive");
}

pair<bool,long> ChainingSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    if (!checkCompatibility(request, isHandler))
        return make_pair(false, 0L);

    pair<bool,long> ret;
    for (ptr_vector<SessionInitiator>::const_iterator i = m_handlers.begin(); i != m_handlers.end(); ++i) {
        ret = i->run(request, entityID, isHandler);
        if (ret.first)
            return ret;
    }
    throw ConfigurationException("None of the configured SessionInitiators handled the request.");
}
