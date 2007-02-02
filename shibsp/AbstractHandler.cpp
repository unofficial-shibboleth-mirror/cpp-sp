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
 * AbstractHandler.cpp
 * 
 * Base class for handlers based on a DOMPropertySet. 
 */

#include "internal.h"
#include "AbstractHandler.h"

using namespace shibsp;
using namespace xercesc;
using namespace std;

AbstractHandler::AbstractHandler(
    const DOMElement* e, DOMNodeFilter* filter, const map<string,string>* remapper
    ) {
    load(e,log4cpp::Category::getInstance(SHIBSP_LOGCAT".AbstractHandler"),filter,remapper);
}
