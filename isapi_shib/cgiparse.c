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

/* cgiparse.c - URL-encoded parameter parsing

   Scott Cantor
   7/6/03
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <httpext.h>

#include "cgiparse.h"

__declspec(thread) char* pch=NULL;

/* Parsing routines modified from NCSA source. */
char *makeword(char *line, char stop)
{
    int x = 0,y;
    char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

    for(x=0;((line[x]) && (line[x] != stop));x++)
        word[x] = line[x];

    word[x] = '\0';
    if(line[x])
        ++x;
    y=0;

    while(line[y++] = line[x++]);
    return word;
}

char *fmakeword(char stop, int *cl)
{
    int wsize;
    char *word;
    int ll;

    wsize = 1024;
    ll=0;
    word = (char *) malloc(sizeof(char) * (wsize + 1));

    while(1)
    {
        word[ll] = *(pch++);
        if(ll==wsize-1)
        {
            word[ll+1] = '\0';
            wsize+=1024;
            word = (char *)realloc(word,sizeof(char)*(wsize+1));
        }
        --(*cl);
        if((word[ll] == stop) || word[ll] == EOF || (!(*cl)))
        {
            if(word[ll] != stop)
                ll++;
            word[ll] = '\0';
            return word;
        }
        ++ll;
    }
}

char x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void unescape_url(char *url)
{
    register int x,y;

    for(x=0,y=0;url[y];++x,++y)
    {
        if((url[x] = url[y]) == '%')
        {
            url[x] = x2c(&url[y+1]);
            y+=2;
        }
    }
    url[x] = '\0';
}

void plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}

typedef struct Query
{
    char* name;
    char* value;
    struct Query* next;
} Query;

HQUERY ParseQuery(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    int cl;
    HQUERY hQuery=NULL;
    HQUERY hLast=NULL;

    /* Verify method and content type. */
    if(!stricmp(lpECB->lpszMethod,"POST"))
    {
        if (stricmp(lpECB->lpszContentType,"application/x-www-form-urlencoded"))
            return NULL;
        pch=lpECB->lpbData;
        cl=lpECB->cbAvailable;
    }
    else if (!stricmp(lpECB->lpszMethod,"GET"))
    {
        pch=lpECB->lpszQueryString;
        cl=strlen(pch);
    }
    else
        return NULL;
        
    while (cl && pch)
    {
        if (hQuery==NULL)
        {
            hQuery=malloc(sizeof(Query));
            hQuery->name=hQuery->value=hQuery->next=NULL;
            hLast=hQuery;
        }
        else
        {
            hLast->next=malloc(sizeof(Query));
            hLast=hLast->next;
            hLast->name=hLast->value=hLast->next=NULL;
        }

        /* hLast is now the current block to use. */
        hLast->value=fmakeword('&',&cl);
        plustospace(hLast->value);
        unescape_url(hLast->value);
        hLast->name=makeword(hLast->value,'=');
    }
    return hQuery;
}

void DeleteQuery(HQUERY hQuery)
{
    if (hQuery!=NULL)
    {
        DeleteQuery(hQuery->next);
        free(hQuery->name);
        free(hQuery->value);
    }
}

const char* QueryValue(HQUERY hQuery, const char* name)
{
    while (hQuery)
    {
        if (!strcmp(name,hQuery->name))
            return hQuery->value;
        else
            hQuery=hQuery->next;
    }
    return NULL;
}
