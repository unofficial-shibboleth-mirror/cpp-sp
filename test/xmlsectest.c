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

/* xmlsectest.c - a test program for xmlsec usage

   Scott Cantor
   11/17/02

   $History:$
*/

#include <curl/curl.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>

int main(int argc, char* argv[])
{
    int ret;
    xmlSecX509StorePtr pStore=NULL;
    xmlSecX509DataPtr pX509=NULL;
    xmlSecKeyPtr key=NULL;

    if (curl_global_init(CURL_GLOBAL_ALL))
    {
        fprintf(stderr,"failed to initialize libcurl, SSL, or Winsock\n");
        return -1;
    }
    fprintf(stderr,"libcurl initialization complete\n");

    xmlInitParser();
    fprintf(stderr,"libxml2 initialization complete\n");

    xmlSecInit();
    fprintf(stderr,"xmlsec initialization complete\n");

    // To get the bloody key to work, we have to do things to fool xmlsec into allowing it.
    // First we load the cert in as a trusted root.
    pStore=xmlSecX509StoreCreate();
    if (!pStore)
    {
        fprintf(stderr,"xmlSecX509StoreCreate failed\n");
        return -1;
    }

    ret=xmlSecX509StoreLoadPemCert(pStore,argv[1],1);
    if (ret<0)
    {
        xmlSecX509StoreDestroy(pStore);
        fprintf(stderr,"unable to load certificate from file: %s\n",argv[1]);
        return -1;
    }

    pX509=xmlSecX509DataCreate();
    if (!pX509)
    {
        xmlSecX509StoreDestroy(pStore);
        fprintf(stderr,"xmlSecX509DataCreate failed\n");
        return -1;
    }

    // Now load the cert again and "verify" the cert against itself, which will mark it verified.
    if (xmlSecX509DataReadPemCert(pX509,argv[1])<0 || xmlSecX509StoreVerify(pStore,pX509)<0)
    {
        xmlSecX509DataDestroy(pX509);
        xmlSecX509StoreDestroy(pStore);
        fprintf(stderr,"unable to load certificate and verify against itself\n");
        return -1;
    }

    // Now we can get the key out.
    key=xmlSecX509DataCreateKey(pX509);
    if (!key)
    {
        xmlSecX509StoreDestroy(pStore);
        fprintf(stderr,"failed to extract key from certificate\n");
        return -1;
    }

    fprintf(stderr,"test completed successfully\n");
    return 0;
}
