/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* ReloadableXMLFile.cpp - basic implementation of a reloadable XML config file

   Scott Cantor
   1/6/04

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <xercesc/framework/LocalFileInputSource.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

ReloadableXMLFileImpl::ReloadableXMLFileImpl(const DOMElement* e) : m_doc(NULL), m_root(e) {}

ReloadableXMLFileImpl::ReloadableXMLFileImpl(const char* pathname) : m_doc(NULL), m_root(NULL)
{
#ifdef _DEBUG
    NDC ndc("ReloadableXMLFileImpl");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ReloadableXMLFileImpl");

    saml::XML::Parser p;
    try
    {
        //static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        auto_ptr_XMLCh widenit(pathname);
        LocalFileInputSource src(widenit.get());
        Wrapper4InputSource dsrc(&src,false);
        m_doc=p.parse(dsrc);
        m_root=m_doc->getDocumentElement();

        log.infoStream() << "Loaded and parsed XML file (" << pathname << ")" << CategoryStream::ENDLINE;
    }
    catch (XMLException& e)
    {
        auto_ptr_char msg(e.getMessage());
        log.errorStream() << "Xerces error while opening configuration file (" << pathname << "): " << msg.get() << CategoryStream::ENDLINE;
        if (m_doc) {
            m_doc->release();
            m_doc=NULL;
        }
        throw MalformedException(msg.get());
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing configuration file (" << pathname << "): " << e.what() << CategoryStream::ENDLINE;
        if (m_doc) {
            m_doc->release();
            m_doc=NULL;
        }
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log.errorStream() << "Unexpected error while parsing configuration file (" << pathname << ")" << CategoryStream::ENDLINE;
        if (m_doc) {
            m_doc->release();
            m_doc=NULL;
        }
        throw;
    }
#endif
}

ReloadableXMLFileImpl::~ReloadableXMLFileImpl()
{
    if (m_doc) {
        m_doc->release();
        m_doc=NULL;
    }
}

ReloadableXMLFile::ReloadableXMLFile(const DOMElement* e) : m_root(e), m_impl(NULL), m_filestamp(0), m_lock(NULL)
{
    static const XMLCh uri[] = { chLatin_u, chLatin_r, chLatin_i, chNull };
    const XMLCh* pathname=e->getAttributeNS(NULL,uri);
    if (pathname && *pathname)
    {
        auto_ptr_char temp(pathname);
        m_source=temp.get();

#ifdef WIN32
        struct _stat stat_buf;
        if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
        struct stat stat_buf;
        if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
            m_filestamp=stat_buf.st_mtime;
        m_lock=RWLock::create();
    }
}

void ReloadableXMLFile::lock()
{
    if (!m_lock)
        return;
        
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
        {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
            {
                try
                {
                    // Update the timestamp regardless. No point in repeatedly trying.
                    m_filestamp=stat_buf.st_mtime;
                    ReloadableXMLFileImpl* new_config=newImplementation(m_source.c_str(),false);
                    delete m_impl;
                    m_impl=new_config;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    Category::getInstance(SHIB_LOGCAT".ReloadableXMLFile").error("failed to reload config file, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    Category::getInstance(SHIB_LOGCAT".ReloadableXMLFile").error("caught an unknown exception, sticking with what we have");
                }
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
}

ReloadableXMLFileImpl* ReloadableXMLFile::getImplementation() const
{
    if (!m_impl) {
        if (m_source.empty())
            m_impl=newImplementation(saml::XML::getFirstChildElement(m_root));
        else
            m_impl=newImplementation(m_source.c_str());
    }
    return m_impl;
}
