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
 * version.cpp
 *
 * Library version macros and constants.
 */

#include "internal.h"
#include "version.h"

SHIBSP_API const char* const    gShibSPVersionStr = SHIBSP_VERSIONSTR;
SHIBSP_API const char* const    gShibSPFullVersionStr = SHIBSP_FULLVERSIONSTR;
SHIBSP_API const char* const    gShibSPDotVersionStr = SHIBSP_FULLVERSIONDOT;
SHIBSP_API const unsigned int   gShibSPMajVersion = SHIBSP_VERSION_MAJOR;
SHIBSP_API const unsigned int   gShibSPMinVersion = SHIBSP_VERSION_MINOR;
SHIBSP_API const unsigned int   gShibSPRevision   = SHIBSP_VERSION_REVISION;
