/*
 *  Copyright 2001-2006 Internet2
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
 * @file shibsp/exceptions.h
 * 
 * Exception classes
 */
 
#ifndef __shibsp_exceptions_h__
#define __shibsp_exceptions_h__

#include <shibsp/base.h>
#include <saml/exceptions.h>

namespace shibsp {
    
    DECL_XMLTOOLING_EXCEPTION(ConfigurationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during configuration.);
    DECL_XMLTOOLING_EXCEPTION(ListenerException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during inter-process communication.);

};

#endif /* __shibsp_exceptions_h__ */
