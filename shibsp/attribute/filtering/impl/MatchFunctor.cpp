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
 * MatchFunctor.cpp
 * 
 * A function that evaluates whether an expressed criteria is met by the current filter context.
 */

#include "internal.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"
#include "util/SPConstants.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

#define DECL_FACTORY(name) \
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,xmltooling::QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory name##Factory

#define DECL_PUBLIC_QNAME(name,lit) \
    xmltooling::QName shibsp::name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_NS, lit)

#define DECL_BASIC_QNAME(name,lit) \
    SHIBSP_DLLLOCAL static xmltooling::QName Deprecated##name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, lit)

#define DECL_SAML_QNAME(name,lit) \
    SHIBSP_DLLLOCAL static xmltooling::QName Deprecated##name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_SAML_NS, lit)

#define REGISTER_FACTORY(name) \
    mgr.registerFactory(name##Type, name##Factory); \
    mgr.registerFactory(Deprecated##name##Type, name##Factory)

namespace shibsp {
    DECL_FACTORY(AnyMatchFunctor);
    DECL_FACTORY(AndMatchFunctor);
    DECL_FACTORY(OrMatchFunctor);
    DECL_FACTORY(NotMatchFunctor);
    DECL_FACTORY(AttributeIssuerString);
    DECL_FACTORY(AttributeRequesterString);
    DECL_FACTORY(AuthenticationMethodString);
    DECL_FACTORY(AttributeValueString);
    DECL_FACTORY(AttributeScopeString);
    DECL_FACTORY(AttributeIssuerRegex);
    DECL_FACTORY(AttributeRequesterRegex);
    DECL_FACTORY(AuthenticationMethodRegex);
    DECL_FACTORY(AttributeValueRegex);
    DECL_FACTORY(AttributeScopeRegex);
    DECL_FACTORY(NumberOfAttributeValues);
    DECL_FACTORY(AttributeIssuerInEntityGroup);
    DECL_FACTORY(AttributeRequesterInEntityGroup);
    DECL_FACTORY(AttributeIssuerEntityAttributeExactMatch);
    DECL_FACTORY(AttributeRequesterEntityAttributeExactMatch);
    DECL_FACTORY(AttributeIssuerEntityAttributeRegexMatch);
    DECL_FACTORY(AttributeRequesterEntityAttributeRegexMatch);
    DECL_FACTORY(AttributeIssuerNameIDFormat);
    DECL_FACTORY(AttributeRequesterNameIDFormat);
    DECL_FACTORY(AttributeIssuerEntityMatcher);
    DECL_FACTORY(AttributeRequesterEntityMatcher);
    DECL_FACTORY(AttributeScopeMatchesShibMDScope);
    DECL_FACTORY(AttributeValueMatchesShibMDScope);
    DECL_FACTORY(NameIDQualifierString);
    DECL_FACTORY(AttributeIssuerRegistrationAuthority);
    DECL_FACTORY(RegistrationAuthority);


    static const XMLCh ANY[] =                          UNICODE_LITERAL_3(A,N,Y);
    static const XMLCh AND[] =                          UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =                           UNICODE_LITERAL_2(O,R);
    static const XMLCh NOT[] =                          UNICODE_LITERAL_3(N,O,T);

    static const XMLCh AttributeIssuerString[] =        UNICODE_LITERAL_21(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,S,t,r,i,n,g);
    static const XMLCh Issuer[] =                       UNICODE_LITERAL_6(I,s,s,u,e,r);

    static const XMLCh AttributeRequesterString[] =     UNICODE_LITERAL_24(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,S,t,r,i,n,g);
    static const XMLCh Requester[] =                    UNICODE_LITERAL_9(R,e,q,u,e,s,t,e,r);

    static const XMLCh AuthenticationMethodString[] =   UNICODE_LITERAL_26(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d,S,t,r,i,n,g);
    static const XMLCh AuthenticationMethod[] =         UNICODE_LITERAL_20(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d);

    static const XMLCh AttributeValueString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,V,a,l,u,e,S,t,r,i,n,g);
    static const XMLCh Value[] =                        UNICODE_LITERAL_5(V,a,l,u,e);

    static const XMLCh AttributeScopeString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,S,c,o,p,e,S,t,r,i,n,g);
    static const XMLCh Scope[] =                        UNICODE_LITERAL_5(S,c,o,p,e);

    static const XMLCh AttributeIssuerRegex[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,R,e,g,e,x);
    static const XMLCh IssuerRegex[] =                  UNICODE_LITERAL_11(I,s,s,u,e,r,R,e,g,e,x);

    static const XMLCh AttributeRequesterRegex[] =      UNICODE_LITERAL_23(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,R,e,g,e,x);
    static const XMLCh RequesterRegex[] =               UNICODE_LITERAL_14(R,e,q,u,e,s,t,e,r,R,e,g,e,x);

    static const XMLCh AuthenticationMethodRegex[] =    UNICODE_LITERAL_25(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d,R,e,g,e,x);

    static const XMLCh AttributeValueRegex[] =          UNICODE_LITERAL_19(A,t,t,r,i,b,u,t,e,V,a,l,u,e,R,e,g,e,x);
    static const XMLCh ValueRegex[] =                   UNICODE_LITERAL_10(V,a,l,u,e,R,e,g,e,x);

    static const XMLCh AttributeScopeRegex[] =          UNICODE_LITERAL_19(A,t,t,r,i,b,u,t,e,S,c,o,p,e,R,e,g,e,x);
    static const XMLCh ScopeRegex[] =                   UNICODE_LITERAL_10(S,c,o,p,e,R,e,g,e,x);

    static const XMLCh NumberOfAttributeValues[] =      UNICODE_LITERAL_23(N,u,m,b,e,r,O,f,A,t,t,r,i,b,u,t,e,V,a,l,u,e,s);

    static const XMLCh AttributeIssuerEntityAttributeExactMatch[] = UNICODE_LITERAL_40(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,E,x,a,c,t,M,a,t,c,h);
    static const XMLCh IssuerEntityAttributeExactMatch[] = UNICODE_LITERAL_31(I,s,s,u,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,E,x,a,c,t,M,a,t,c,h);

    static const XMLCh AttributeRequesterEntityAttributeExactMatch[] = UNICODE_LITERAL_43(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,E,x,a,c,t,M,a,t,c,h);
    static const XMLCh EntityAttributeExactMatch[] = 	UNICODE_LITERAL_25(E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,E,x,a,c,t,M,a,t,c,h);

    static const XMLCh AttributeIssuerEntityAttributeRegexMatch[] = UNICODE_LITERAL_40(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,R,e,g,e,x,M,a,t,c,h);
    static const XMLCh IssuerEntityAttributeRegexMatch[] = UNICODE_LITERAL_31(I,s,s,u,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,R,e,g,e,x,M,a,t,c,h);

    static const XMLCh AttributeRequesterEntityAttributeRegexMatch[] = UNICODE_LITERAL_43(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,R,e,g,e,x,M,a,t,c,h);
    static const XMLCh EntityAttributeRegexMatch[] = 	UNICODE_LITERAL_25(E,n,t,i,t,y,A,t,t,r,i,b,u,t,e,R,e,g,e,x,M,a,t,c,h);

    static const XMLCh IssuerNameIDFormatExactMatch[] = UNICODE_LITERAL_28(I,s,s,u,e,r,N,a,m,e,I,D,F,o,r,m,a,t,E,x,a,c,t,M,a,t,c,h);
    static const XMLCh NameIDFormatExactMatch[] =       UNICODE_LITERAL_22(N,a,m,e,I,D,F,o,r,m,a,t,E,x,a,c,t,M,a,t,c,h);

    static const XMLCh AttributeIssuerInEntityGroup[] = UNICODE_LITERAL_28(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,I,n,E,n,t,i,t,y,G,r,o,u,p);
    static const XMLCh IssuerInEntityGroup[] =          UNICODE_LITERAL_19(I,s,s,u,e,r,I,n,E,n,t,i,t,y,G,r,o,u,p);

    static const XMLCh AttributeRequesterInEntityGroup[] = UNICODE_LITERAL_31(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,I,n,E,n,t,i,t,y,G,r,o,u,p);
    static const XMLCh InEntityGroup[] = 				UNICODE_LITERAL_13(I,n,E,n,t,i,t,y,G,r,o,u,p);

    static const XMLCh AttributeIssuerRegistrationAuthority[] = UNICODE_LITERAL_36(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,R,e,g,i,s,t,r,a,t,i,o,n,A,u,t,h,o,r,i,t,y);
    static const XMLCh IssuerRegistrationAuthority[] = UNICODE_LITERAL_27(I,s,s,u,e,r,R,e,g,i,s,t,r,a,t,i,o,n,A,u,t,h,o,r,i,t,y);

    static const XMLCh RegistrationAuthority[] =        UNICODE_LITERAL_21(R,e,g,i,s,t,r,a,t,i,o,n,A,u,t,h,o,r,i,t,y);

    static const XMLCh AttributeScopeMatchesShibMDScope[] = UNICODE_LITERAL_32(A,t,t,r,i,b,u,t,e,S,c,o,p,e,M,a,t,c,h,e,s,S,h,i,b,M,D,S,c,o,p,e);
    static const XMLCh ScopeMatchesShibMDScope[] =          UNICODE_LITERAL_23(S,c,o,p,e,M,a,t,c,h,e,s,S,h,i,b,M,D,S,c,o,p,e);

    static const XMLCh AttributeValueMatchesShibMDScope[] = UNICODE_LITERAL_32(A,t,t,r,i,b,u,t,e,V,a,l,u,e,M,a,t,c,h,e,s,S,h,i,b,M,D,S,c,o,p,e);
    static const XMLCh ValueMatchesShibMDScope[] =          UNICODE_LITERAL_23(V,a,l,u,e,M,a,t,c,h,e,s,S,h,i,b,M,D,S,c,o,p,e);

    static const XMLCh NameIDQualifierString[] =        UNICODE_LITERAL_21(N,a,m,e,I,D,Q,u,a,l,i,f,i,e,r,S,t,r,i,n,g);
    static const XMLCh AttributeIssuerEntityMatcher[] = UNICODE_LITERAL_28(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,E,n,t,i,t,y,M,a,t,c,h,e,r);
    static const XMLCh AttributeRequesterEntityMatcher[] = UNICODE_LITERAL_31(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,E,n,t,i,t,y,M,a,t,c,h,e,r);
};

DECL_PUBLIC_QNAME(AnyMatchFunctor, ANY);
DECL_BASIC_QNAME(AnyMatchFunctor, ANY);

DECL_PUBLIC_QNAME(AndMatchFunctor, AND);
DECL_BASIC_QNAME(AndMatchFunctor, AND);

DECL_PUBLIC_QNAME(OrMatchFunctor, OR);
DECL_BASIC_QNAME(OrMatchFunctor, OR);

DECL_PUBLIC_QNAME(NotMatchFunctor, NOT);
DECL_BASIC_QNAME(NotMatchFunctor, NOT);

DECL_PUBLIC_QNAME(AttributeIssuerString, Issuer);
DECL_BASIC_QNAME(AttributeIssuerString, AttributeIssuerString);

DECL_PUBLIC_QNAME(AttributeRequesterString, Requester);
DECL_BASIC_QNAME(AttributeRequesterString, AttributeRequesterString);

DECL_PUBLIC_QNAME(AuthenticationMethodString, AuthenticationMethod);
DECL_BASIC_QNAME(AuthenticationMethodString, AuthenticationMethodString);

DECL_PUBLIC_QNAME(AttributeValueString, Value);
DECL_BASIC_QNAME(AttributeValueString, AttributeValueString);

DECL_PUBLIC_QNAME(AttributeScopeString, Scope);
DECL_BASIC_QNAME(AttributeScopeString, AttributeScopeString);

DECL_PUBLIC_QNAME(AttributeIssuerRegex, IssuerRegex);
DECL_BASIC_QNAME(AttributeIssuerRegex, AttributeIssuerRegex);

DECL_PUBLIC_QNAME(AttributeRequesterRegex, RequesterRegex);
DECL_BASIC_QNAME(AttributeRequesterRegex, AttributeRequesterRegex);

DECL_PUBLIC_QNAME(AuthenticationMethodRegex, AuthenticationMethodRegex);
DECL_BASIC_QNAME(AuthenticationMethodRegex, AuthenticationMethodRegex);

DECL_PUBLIC_QNAME(AttributeValueRegex, ValueRegex);
DECL_BASIC_QNAME(AttributeValueRegex, AttributeValueRegex);

DECL_PUBLIC_QNAME(AttributeScopeRegex, ScopeRegex);
DECL_BASIC_QNAME(AttributeScopeRegex, AttributeScopeRegex);

DECL_PUBLIC_QNAME(NumberOfAttributeValues, NumberOfAttributeValues);
DECL_BASIC_QNAME(NumberOfAttributeValues, NumberOfAttributeValues);

DECL_PUBLIC_QNAME(AttributeIssuerEntityAttributeExactMatch, IssuerEntityAttributeExactMatch);
DECL_SAML_QNAME(AttributeIssuerEntityAttributeExactMatch, AttributeIssuerEntityAttributeExactMatch);

DECL_PUBLIC_QNAME(AttributeRequesterEntityAttributeExactMatch, EntityAttributeExactMatch);
DECL_SAML_QNAME(AttributeRequesterEntityAttributeExactMatch, AttributeRequesterEntityAttributeExactMatch);
DECL_SAML_QNAME(EntityAttributeExactMatch, EntityAttributeExactMatch);

DECL_PUBLIC_QNAME(AttributeIssuerEntityAttributeRegexMatch, IssuerEntityAttributeRegexMatch);
DECL_SAML_QNAME(AttributeIssuerEntityAttributeRegexMatch, AttributeIssuerEntityAttributeRegexMatch);

DECL_PUBLIC_QNAME(AttributeRequesterEntityAttributeRegexMatch, EntityAttributeRegexMatch);
DECL_SAML_QNAME(AttributeRequesterEntityAttributeRegexMatch, AttributeRequesterEntityAttributeRegexMatch);
DECL_SAML_QNAME(EntityAttributeRegexMatch, EntityAttributeRegexMatch);

DECL_PUBLIC_QNAME(AttributeIssuerNameIDFormat, IssuerNameIDFormatExactMatch);
DECL_PUBLIC_QNAME(AttributeRequesterNameIDFormat, NameIDFormatExactMatch);

DECL_PUBLIC_QNAME(AttributeIssuerInEntityGroup, IssuerInEntityGroup);
DECL_SAML_QNAME(AttributeIssuerInEntityGroup, AttributeIssuerInEntityGroup);

DECL_PUBLIC_QNAME(AttributeRequesterInEntityGroup, InEntityGroup);
DECL_SAML_QNAME(AttributeRequesterInEntityGroup, AttributeRequesterInEntityGroup);
DECL_SAML_QNAME(InEntityGroup, InEntityGroup);

DECL_PUBLIC_QNAME(AttributeIssuerRegistrationAuthority, IssuerRegistrationAuthority);
DECL_SAML_QNAME(AttributeIssuerRegistrationAuthority, AttributeIssuerRegistrationAuthority);

DECL_PUBLIC_QNAME(RegistrationAuthority, RegistrationAuthority);
DECL_SAML_QNAME(RegistrationAuthority, RegistrationAuthority);

DECL_PUBLIC_QNAME(AttributeScopeMatchesShibMDScope, ScopeMatchesShibMDScope);
DECL_SAML_QNAME(AttributeScopeMatchesShibMDScope, AttributeScopeMatchesShibMDScope);

DECL_PUBLIC_QNAME(AttributeValueMatchesShibMDScope, ValueMatchesShibMDScope);
DECL_SAML_QNAME(AttributeValueMatchesShibMDScope, AttributeValueMatchesShibMDScope);

DECL_PUBLIC_QNAME(NameIDQualifierString, NameIDQualifierString);
DECL_SAML_QNAME(NameIDQualifierString, NameIDQualifierString);

DECL_PUBLIC_QNAME(AttributeIssuerEntityMatcher, AttributeIssuerEntityMatcher);
DECL_SAML_QNAME(AttributeIssuerEntityMatcher, AttributeIssuerEntityMatcher);

DECL_PUBLIC_QNAME(AttributeRequesterEntityMatcher, AttributeRequesterEntityMatcher);
DECL_SAML_QNAME(AttributeRequesterEntityMatcher, AttributeRequesterEntityMatcher);

void SHIBSP_API shibsp::registerMatchFunctors()
{
    PluginManager< MatchFunctor,xmltooling::QName,pair<const FilterPolicyContext*,const DOMElement*> >& mgr =
        SPConfig::getConfig().MatchFunctorManager;

    REGISTER_FACTORY(AnyMatchFunctor);
    REGISTER_FACTORY(AndMatchFunctor);
    REGISTER_FACTORY(OrMatchFunctor);
    REGISTER_FACTORY(NotMatchFunctor);
    REGISTER_FACTORY(AttributeIssuerString);
    REGISTER_FACTORY(AttributeRequesterString);
    REGISTER_FACTORY(AuthenticationMethodString);
    REGISTER_FACTORY(AttributeValueString);
    REGISTER_FACTORY(AttributeScopeString);
    REGISTER_FACTORY(AttributeIssuerRegex);
    REGISTER_FACTORY(AttributeRequesterRegex);
    REGISTER_FACTORY(AuthenticationMethodRegex);
    REGISTER_FACTORY(AttributeValueRegex);
    REGISTER_FACTORY(AttributeScopeRegex);
    REGISTER_FACTORY(NumberOfAttributeValues);
    REGISTER_FACTORY(AttributeIssuerEntityAttributeExactMatch);
    REGISTER_FACTORY(AttributeRequesterEntityAttributeExactMatch);
    REGISTER_FACTORY(AttributeIssuerEntityAttributeRegexMatch);
    REGISTER_FACTORY(AttributeRequesterEntityAttributeRegexMatch);
    REGISTER_FACTORY(AttributeIssuerInEntityGroup);
    REGISTER_FACTORY(AttributeRequesterInEntityGroup);
    REGISTER_FACTORY(AttributeIssuerRegistrationAuthority);
    REGISTER_FACTORY(RegistrationAuthority);
    REGISTER_FACTORY(AttributeScopeMatchesShibMDScope);
    REGISTER_FACTORY(AttributeValueMatchesShibMDScope);
    REGISTER_FACTORY(NameIDQualifierString);
    REGISTER_FACTORY(AttributeIssuerEntityMatcher);
    REGISTER_FACTORY(AttributeRequesterEntityMatcher);

    // Explicit because there are no deprecated versions to register.
    mgr.registerFactory(AttributeIssuerNameIDFormatType, AttributeIssuerNameIDFormatFactory);
    mgr.registerFactory(AttributeRequesterNameIDFormatType, AttributeRequesterNameIDFormatFactory);

    // Extra aliases for some deprecated types.
    mgr.registerFactory(DeprecatedEntityAttributeExactMatchType, AttributeRequesterEntityAttributeExactMatchFactory);
    mgr.registerFactory(DeprecatedEntityAttributeRegexMatchType, AttributeRequesterEntityAttributeRegexMatchFactory);
    mgr.registerFactory(DeprecatedInEntityGroupType, AttributeRequesterInEntityGroupFactory);
}

MatchFunctor::MatchFunctor()
{
}

MatchFunctor::~MatchFunctor()
{
}

FilterPolicyContext::FilterPolicyContext(multimap<string,MatchFunctor*>& functors) : m_functors(functors)
{
}

FilterPolicyContext::~FilterPolicyContext()
{
}

multimap<string,MatchFunctor*>& FilterPolicyContext::getMatchFunctors() const
{
    return m_functors;
}
