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

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    //SHIBSP_DLLLOCAL PluginManager<MatchFunctor,QName,const DOMElement*>::Factory FunctorFactory;
};

void SHIBSP_API shibsp::registerMatchFunctors()
{
    SPConfig& conf = SPConfig::getConfig();
    //conf.MatchFunctorManager.registerFactory("", FunctorFactory);
}
