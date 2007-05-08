/*
 *  Copyright 2001-2007 Internet2
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

/**
 * MatchFunctor.cpp
 * 
 * A function that evaluates whether an expressed criteria is met by the current filter context.
 */

#include "internal.h"
#include "attribute/filtering/MatchFunctor.h"
#include "util/SPConstants.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

#define DECL_FACTORY(name) \
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory name##Factory

#define DECL_BASIC_QNAME(name,lit) \
    QName shibsp::name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, lit)

#define REGISTER_FACTORY(name) \
    mgr.registerFactory(name##Type, name##Factory)

namespace shibsp {
    DECL_FACTORY(AnyMatchFunctor);
    DECL_FACTORY(AndMatchFunctor);
    DECL_FACTORY(OrMatchFunctor);
    DECL_FACTORY(NotMatchFunctor);
    DECL_FACTORY(AttributeRequesterString);
    DECL_FACTORY(AttributeIssuerString);
    DECL_FACTORY(AuthenticationMethodString);
    DECL_FACTORY(AttributeValueString);
    DECL_FACTORY(AttributeScopeString);

    static const XMLCh ANY[] =                          UNICODE_LITERAL_3(A,N,Y);
    static const XMLCh AND[] =                          UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =                           UNICODE_LITERAL_2(O,R);
    static const XMLCh NOT[] =                          UNICODE_LITERAL_3(N,O,T);
    static const XMLCh AttributeRequesterString[] =     UNICODE_LITERAL_24(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,S,t,r,i,n,g);
    static const XMLCh AttributeIssuerString[] =        UNICODE_LITERAL_21(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,S,t,r,i,n,g);
    static const XMLCh AuthenticationMethodString[] =   UNICODE_LITERAL_26(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d,S,t,r,i,n,g);
    static const XMLCh AttributeValueString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,V,a,l,u,e,S,t,r,i,n,g);
    static const XMLCh AttributeScopeString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,S,c,o,p,e,S,t,r,i,n,g);
};

DECL_BASIC_QNAME(AnyMatchFunctor, ANY);
DECL_BASIC_QNAME(AndMatchFunctor, AND);
DECL_BASIC_QNAME(OrMatchFunctor, OR);
DECL_BASIC_QNAME(NotMatchFunctor, NOT);
DECL_BASIC_QNAME(AttributeRequesterString, AttributeRequesterString);
DECL_BASIC_QNAME(AttributeIssuerString, AttributeIssuerString);
DECL_BASIC_QNAME(AuthenticationMethodString, AuthenticationMethodString);
DECL_BASIC_QNAME(AttributeValueString, AttributeValueString);
DECL_BASIC_QNAME(AttributeScopeString, AttributeScopeString);

void SHIBSP_API shibsp::registerMatchFunctors()
{
    PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >& mgr =
        SPConfig::getConfig().MatchFunctorManager;
    REGISTER_FACTORY(AnyMatchFunctor);
    REGISTER_FACTORY(AndMatchFunctor);
    REGISTER_FACTORY(OrMatchFunctor);
    REGISTER_FACTORY(NotMatchFunctor);
    REGISTER_FACTORY(AttributeRequesterString);
    REGISTER_FACTORY(AttributeIssuerString);
    REGISTER_FACTORY(AuthenticationMethodString);
    REGISTER_FACTORY(AttributeValueString);
    REGISTER_FACTORY(AttributeScopeString);
}
