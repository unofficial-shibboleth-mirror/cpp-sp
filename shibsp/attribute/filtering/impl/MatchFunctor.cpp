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

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory AnyFunctorFactory;
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory AndFunctorFactory;
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory OrFunctorFactory;
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory NotFunctorFactory;

    static const XMLCh ANY[] =                  UNICODE_LITERAL_3(A,N,Y);
    static const XMLCh AND[] =                  UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =                   UNICODE_LITERAL_2(O,R);
    static const XMLCh NOT[] =                  UNICODE_LITERAL_3(N,O,T);
};

QName shibsp::AnyMatchFunctorType(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, ANY);
QName shibsp::AndMatchFunctorType(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, AND);
QName shibsp::OrMatchFunctorType(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, OR);
QName shibsp::NotMatchFunctorType(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, NOT);

void SHIBSP_API shibsp::registerMatchFunctors()
{
    SPConfig& conf = SPConfig::getConfig();
    conf.MatchFunctorManager.registerFactory(AnyMatchFunctorType, AnyFunctorFactory);
    conf.MatchFunctorManager.registerFactory(AndMatchFunctorType, AndFunctorFactory);
    conf.MatchFunctorManager.registerFactory(OrMatchFunctorType, OrFunctorFactory);
    conf.MatchFunctorManager.registerFactory(NotMatchFunctorType, NotFunctorFactory);
}
