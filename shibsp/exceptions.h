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
 * @file shibsp/exceptions.h
 * 
 * Exception classes.
 */
 
#ifndef __shibsp_exceptions_h__
#define __shibsp_exceptions_h__

#include <shibsp/base.h>
#include <xmltooling/exceptions.h>

namespace shibsp {
    
    DECL_XMLTOOLING_EXCEPTION(AttributeException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during attribute processing.);
    DECL_XMLTOOLING_EXCEPTION(ConfigurationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during configuration.);
    DECL_XMLTOOLING_EXCEPTION(ListenerException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during inter-process communication.);
    DECL_XMLTOOLING_EXCEPTION(SessionException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during session processing.);

};

#endif /* __shibsp_exceptions_h__ */
