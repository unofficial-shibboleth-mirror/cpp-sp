/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * remoting/impl/ddf.cpp
 *
 * C++ DDF abstraction for interpretive RPC
 */

#include "internal.h"
#include "remoting/ddf.h"
#include "util/Misc.h"

#include <stdexcept>
#include <iomanip>
#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

// defensive string functions

size_t ddf_strlen(const char* s)
{
    return s ? strlen(s) : 0;
}

char* ddf_strdup(const char* s)
{
    return (s && *s) ? strdup(s) : nullptr;
}

#define MAX_NAME_LEN 255

/* Parses '.' notation paths, where each component is at most MAX_NAME_LEN long.
   path contains the address of a constant string which is the current path.
   name points to a buffer in which to place the first path component.
   After execution, the path pointer will be moved past the first dot.
   The actual path string is never modified. Only name is written to.
   The name buffer is returned from the function. */
char* ddf_token(const char** path, char* name)
{
    *name=0;
    if (*path==nullptr || **path==0)
        return name;

    const char* temp=strchr(*path,'.');
    if (temp==nullptr) {
        strncpy(name,*path,MAX_NAME_LEN);
        name[MAX_NAME_LEN]=0;
        *path=nullptr;
    }
    else if (temp>*path) {
        strncpy(name,*path,temp-*path);
        name[temp-*path]=0;
        *path=temp+1;
    }
    else
        *path=temp+1;
    return name;
}

// body implementation

struct shibsp::ddf_body_t {
    ddf_body_t() : name(nullptr), parent(nullptr), next(nullptr), prev(nullptr), type(DDF_EMPTY) {}

    char* name;                     // name of node
    ddf_body_t* parent;             // parent node, if any
    ddf_body_t* next;               // next node, if any
    ddf_body_t* prev;               // previous node, if any

    enum {
        DDF_EMPTY,
        DDF_STRING,
        DDF_INT,
        DDF_FLOAT,
        DDF_STRUCT,
        DDF_LIST,
        DDF_STRING_UNSAFE,
        DDF_LONG
    } type;                         // data type of node

    union {
        char* string;
        long integer;
        long long longinteger;
        double floating;
        struct {
            ddf_body_t* first;
            ddf_body_t* last;
            ddf_body_t* current;
            unsigned long count;
        } children;
    } value;                        // value of node
};

// library implementation

DDF::DDF() : m_handle(nullptr)
{
}

DDF::DDF(const char* n)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
}

DDF::DDF(const char* n, const char* val, bool safe)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    string(const_cast<char*>(val), true, safe);
}

DDF::DDF(const char* n, long val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    integer(val);
}

DDF::DDF(const char* n, long long val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    longinteger(val);
}

DDF::DDF(const char* n, double val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    floating(val);
}

DDF& DDF::destroy()
{
    remove().empty().name(nullptr);
    delete m_handle;
    m_handle=nullptr;
    return *this;
}

DDF DDF::copy() const
{
    if (m_handle==nullptr)
        return DDF();

    switch (m_handle->type) {
        case ddf_body_t::DDF_EMPTY:
            return DDF(m_handle->name);
        case ddf_body_t::DDF_STRING:
        case ddf_body_t::DDF_STRING_UNSAFE:
            return DDF(m_handle->name,m_handle->value.string,(m_handle->type==ddf_body_t::DDF_STRING));
        case ddf_body_t::DDF_INT:
            return DDF(m_handle->name,m_handle->value.integer);
        case ddf_body_t::DDF_LONG:
            return DDF(m_handle->name,m_handle->value.longinteger);
        case ddf_body_t::DDF_FLOAT:
            return DDF(m_handle->name,m_handle->value.floating);
        case ddf_body_t::DDF_STRUCT:
        case ddf_body_t::DDF_LIST:
        {
            DDF copy(m_handle->name), temp;
            if (m_handle->type==ddf_body_t::DDF_STRUCT)
                copy.structure();
            else
                copy.list();
            ddf_body_t* child=m_handle->value.children.first;
            while (child) {
                temp.m_handle=child;
                DDF temp2=temp.copy();
                copy.add(temp2);
                if (copy.m_handle==nullptr)
                    return copy;
                if (m_handle->value.children.current==child)
                    copy.m_handle->value.children.current=copy.m_handle->value.children.last;
                child=child->next;
            }
            return copy;
        }
    }
    return DDF();
}

const char* DDF::name() const
{
    return (m_handle) ? m_handle->name : nullptr;
}

DDF& DDF::name(const char* n)
{
    char trunc_name[MAX_NAME_LEN+1]="";

    if (m_handle) {
        if (m_handle->name)
            free(m_handle->name);
        if (n && *n) {
            strncpy(trunc_name, n, MAX_NAME_LEN);
            trunc_name[MAX_NAME_LEN]='\0';
            m_handle->name=ddf_strdup(trunc_name);
            if (!m_handle->name)
                destroy();
        }
        else
            m_handle->name=nullptr;
    }
    return *this;
}

DDF& DDF::name(const std::string& n)
{
    return name(n.c_str());
}

bool DDF::isnull() const
{
    return m_handle ? false : true;
}

bool DDF::isempty() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_EMPTY) : false;
}

bool DDF::isstring() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_STRING || m_handle->type==ddf_body_t::DDF_STRING_UNSAFE) : false;
}

bool DDF::isint() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_INT) : false;
}

bool DDF::islong() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_LONG) : false;
}

bool DDF::isfloat() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_FLOAT) : false;
}

bool DDF::isstruct() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_STRUCT) : false;
}

bool DDF::islist() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_LIST) : false;
}

const char* DDF::string() const
{
    return isstring() ? m_handle->value.string : nullptr;
}

long DDF::integer() const
{
    if (m_handle) {
        switch(m_handle->type) {
            case ddf_body_t::DDF_INT:
                return m_handle->value.integer;
            case ddf_body_t::DDF_LONG:
                return m_handle->value.longinteger;
            case ddf_body_t::DDF_FLOAT:
                return static_cast<long>(m_handle->value.floating);
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                return m_handle->value.string ? atol(m_handle->value.string) : 0;
            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
                return m_handle->value.children.count;
            default:
                break;
        }
    }
    return 0;
}

long long DDF::longinteger() const
{
    if (m_handle) {
        switch(m_handle->type) {
            case ddf_body_t::DDF_INT:
                return m_handle->value.integer;
            case ddf_body_t::DDF_LONG:
                return m_handle->value.longinteger;
            case ddf_body_t::DDF_FLOAT:
                return static_cast<long long>(m_handle->value.floating);
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                return m_handle->value.string ? atoll(m_handle->value.string) : 0;
            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
                return m_handle->value.children.count;
            default:
                break;
        }
    }
    return 0;
}

double DDF::floating() const
{
    if (m_handle) {
        switch(m_handle->type) {
            case ddf_body_t::DDF_INT:
                return m_handle->value.integer;
            case ddf_body_t::DDF_LONG:
                return m_handle->value.longinteger;
            case ddf_body_t::DDF_FLOAT:
                return m_handle->value.floating;
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                return m_handle->value.string ? atof(m_handle->value.string) : 0;
            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
                return m_handle->value.children.count;
            default:
                break;
        }
    }
    return 0;
}

size_t DDF::strlen() const
{
    return ddf_strlen(string());
}

bool DDF::operator==(const char* s) const
{
    if (string()==nullptr || s==nullptr)
        return (string()==nullptr && s==nullptr);
    else
        return (::strcmp(string(),s)==0);
}

DDF& DDF::empty()
{
    if (m_handle) {
        switch (m_handle->type) {
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                if (m_handle->value.string)
                    free(m_handle->value.string);
                break;

            case ddf_body_t::DDF_LIST:
            case ddf_body_t::DDF_STRUCT:
            {
                DDF temp;
                while (m_handle->value.children.first)
                {
                    temp.m_handle=m_handle->value.children.first;
                    temp.destroy();
                }
            }

            default:
                break;
        }
        m_handle->type=ddf_body_t::DDF_EMPTY;
    }
    return *this;
}

DDF& DDF::string(char* val, bool copyit, bool safe)
{
    if (empty().m_handle) {
        m_handle->value.string = copyit ? ddf_strdup(val) : val;
        if (!m_handle->value.string && val && *val)
            return destroy();
        m_handle->type=(safe ? ddf_body_t::DDF_STRING : ddf_body_t::DDF_STRING_UNSAFE);
    }
    return *this;
}

DDF& DDF::string(const char* val)
{
    return string(const_cast<char*>(val), true);
}

DDF& DDF::string(const std::string& val)
{
    // Yes, this is horrendous, but we're copying the buffer so the cast shouldn't hurt anything.
    return string(const_cast<char*>(val.c_str()), true);
}

DDF& DDF::unsafe_string(const char* val)
{
    return string(const_cast<char*>(val), true, false);
}

DDF& DDF::string(long val)
{
    std::string buf = boost::lexical_cast<std::string>(val);
    return string(buf.c_str());
}

DDF& DDF::string(double val)
{
    std::string buf = boost::lexical_cast<std::string>(val);
    return string(buf.c_str());
}

DDF& DDF::integer(long val)
{
    if (empty().m_handle) {
        m_handle->value.integer=val;
        m_handle->type=ddf_body_t::DDF_INT;
    }
    return *this;
}

DDF& DDF::integer(const char* val)
{
    if (empty().m_handle) {
        m_handle->value.integer=(val ? atol(val) : 0);
        m_handle->type=ddf_body_t::DDF_INT;
    }
    return *this;
}

DDF& DDF::longinteger(long long val)
{
    if (empty().m_handle) {
        m_handle->value.longinteger=val;
        m_handle->type=ddf_body_t::DDF_LONG;
    }
    return *this;
}

DDF& DDF::longinteger(const char* val)
{
    if (empty().m_handle) {
        m_handle->value.longinteger=(val ? atoll(val) : 0);
        m_handle->type=ddf_body_t::DDF_LONG;
    }
    return *this;
}

DDF& DDF::floating(double val)
{
    if (empty().m_handle) {
        m_handle->value.floating=val;
        m_handle->type=ddf_body_t::DDF_FLOAT;
    }
    return *this;
}

DDF& DDF::floating(const char* val)
{
    if (empty().m_handle) {
        m_handle->value.floating=(val ? atof(val) : 0);
        m_handle->type=ddf_body_t::DDF_FLOAT;
    }
    return *this;
}

DDF& DDF::structure()
{
    if (empty().m_handle) {
        m_handle->type=ddf_body_t::DDF_STRUCT;
        m_handle->value.children.first=nullptr;
        m_handle->value.children.last=nullptr;
        m_handle->value.children.current=nullptr;
        m_handle->value.children.count=0;
    }
    return *this;
}

DDF& DDF::list()
{
    if (empty().m_handle) {
        m_handle->type=ddf_body_t::DDF_LIST;
        m_handle->value.children.first=nullptr;
        m_handle->value.children.last=nullptr;
        m_handle->value.children.current=nullptr;
        m_handle->value.children.count=0;
    }
    return *this;
}

DDF& DDF::add(DDF& child)
{
    if ((!isstruct() && !islist()) || !child.m_handle)
        return child;

    if (m_handle==child.m_handle->parent)
        return child;

    if (isstruct()) {
        if (!child.name())
            return child;
        getmember(child.name()).destroy();
    }

    child.remove();
    if (!m_handle->value.children.first)
        m_handle->value.children.first=child.m_handle;
    else {
        m_handle->value.children.last->next=child.m_handle;
        child.m_handle->prev=m_handle->value.children.last;
    }
    m_handle->value.children.last=child.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

DDF& DDF::addbefore(DDF& child, DDF& before)
{
    if (!islist() || !child.m_handle || !before.m_handle || before.m_handle->parent!=m_handle)
        return child;

    child.remove();
    if (m_handle->value.children.first==before.m_handle)
        m_handle->value.children.first=child.m_handle;
    child.m_handle->prev=before.m_handle->prev;
    if (child.m_handle->prev)
        child.m_handle->prev->next=child.m_handle;
    before.m_handle->prev=child.m_handle;
    child.m_handle->next=before.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

DDF& DDF::addafter(DDF& child, DDF& after)
{
    if (!islist() || !child.m_handle || !after.m_handle || after.m_handle->parent!=m_handle)
        return child;

    child.remove();
    if (m_handle->value.children.last==after.m_handle)
        m_handle->value.children.last=child.m_handle;
    child.m_handle->next=after.m_handle->next;
    if (child.m_handle->next)
        child.m_handle->next->prev=child.m_handle;
    after.m_handle->next=child.m_handle;
    child.m_handle->prev=after.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

void DDF::swap(DDF& arg)
{
    ddf_body_t* temp=arg.m_handle;
    arg.m_handle=m_handle;
    m_handle=temp;
}

DDF& DDF::remove()
{
    if (!m_handle || !m_handle->parent)
        return *this;

    if (m_handle->next)
        m_handle->next->prev=m_handle->prev;

    if (m_handle->prev)
        m_handle->prev->next=m_handle->next;

    if (m_handle->parent->value.children.first==m_handle)
        m_handle->parent->value.children.first=m_handle->next;

    if (m_handle->parent->value.children.last==m_handle)
        m_handle->parent->value.children.last=m_handle->prev;

    if (m_handle->parent->value.children.current==m_handle)
        m_handle->parent->value.children.current=m_handle->prev;

    m_handle->parent->value.children.count--;
    m_handle->parent=nullptr;
    m_handle->next=nullptr;
    m_handle->prev=nullptr;
    return *this;
}

DDF DDF::parent() const
{
    DDF p;

    p.m_handle=(m_handle ? m_handle->parent : nullptr);
    return p;
}

DDF DDF::first()
{
    DDF f;

    if (islist() || isstruct())
        f.m_handle=m_handle->value.children.current=m_handle->value.children.first;
    return f;
}

DDF DDF::next()
{
    DDF n;

    if ((islist() || isstruct()) && m_handle->value.children.current!=m_handle->value.children.last) {
        if (!m_handle->value.children.current)
            n.m_handle=m_handle->value.children.current=m_handle->value.children.first;
        else
            n.m_handle=m_handle->value.children.current=m_handle->value.children.current->next;
    }
    return n;
}

DDF DDF::last()
{
    DDF l;

    if ((islist() || isstruct()) && m_handle->value.children.last) {
        m_handle->value.children.current=m_handle->value.children.last->prev;
        l.m_handle=m_handle->value.children.last;
    }
    return l;
}

DDF DDF::previous()
{
    DDF p;

    if (islist() || isstruct()) {
        p.m_handle=m_handle->value.children.current;
        if (p.m_handle)
            m_handle->value.children.current=m_handle->value.children.current->prev;
    }
    return p;
}

DDF DDF::operator[](const char* path) const
{
    return getmember(path);
}

DDF DDF::operator[](unsigned long index) const
{
    DDF d;

    if (islist() && index<m_handle->value.children.count) {
        for (d.m_handle=m_handle->value.children.first; index; index--)
            d.m_handle=d.m_handle->next;
    }
    else
        throw range_error("DDF object not a list with >=index+1 elements");
    return d;
}

DDF DDF::addmember(const char* path)
{
    char name[MAX_NAME_LEN+1];
    const char* path_ptr=path;

    if (m_handle && ddf_strlen(ddf_token(&path_ptr,name))>0) {
        if (!isstruct())
            structure();

        DDF new_member=getmember(name);
        if (!new_member.m_handle) {
            DDF temp(name);
            new_member=add(temp);
        }

        if (new_member.m_handle) {
            if (ddf_strlen(path_ptr)>0) {
                DDF last_member=new_member.addmember(path_ptr);
                if (!last_member.m_handle)
                    return new_member.destroy();
                else
                    return last_member;
            }
            return new_member;
        }
        return new_member;
    }
    return DDF();
}

DDF DDF::getmember(const char* path) const
{
    DDF current;
    char name[MAX_NAME_LEN+1];
    const char* path_ptr=path;

    ddf_token(&path_ptr, name);
    if (*name == 0)
        return current;
    else if (*name == '[') {
        unsigned long i = strtoul(name+1, nullptr, 10);
        if (islist() && i < m_handle->value.children.count)
            current=operator[](i);
        else if (i == 0)
            current = *this;
    }
    else if (isstruct()) {
        current.m_handle = m_handle->value.children.first;
        while (current.m_handle && strcmp(current.m_handle->name,name) != 0)
            current.m_handle = current.m_handle->next;
    }
    else if (islist()) {
        current.m_handle = m_handle->value.children.first;
        return current.getmember(path);
    }

    if (current.m_handle && path_ptr && *path_ptr)
        current = current.getmember(path_ptr);
    return current;
}


void ddf_print_indent(FILE* f, int indent)
{
    for (; indent>0; indent--)
        putc(' ',f);
}

void DDF::dump(FILE* f, int indent) const
{
    if (!f)
        f=stderr;

    ddf_print_indent(f,indent);
    if (m_handle) {
        switch (m_handle->type) {

            case ddf_body_t::DDF_EMPTY:
                fprintf(f,"empty");
                if (m_handle->name)
                    fprintf(f," %s",m_handle->name);
                break;

            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                if (m_handle->name)
                    fprintf(f,"char* %s = ",m_handle->name);
                else
                    fprintf(f,"char* = ");
                if (const char* chptr=m_handle->value.string) {
                    putc('"',f);
                    while (*chptr)
                        fputc(*chptr++,f);
                    putc('"',f);
                }
                else
                    fprintf(f,"nullptr");
                break;

            case ddf_body_t::DDF_INT:
                if (m_handle->name)
                    fprintf(f,"long %s = ",m_handle->name);
                else
                    fprintf(f,"long = ");
                fprintf(f,"%ld",m_handle->value.integer);
                break;

            case ddf_body_t::DDF_LONG:
                if (m_handle->name)
                    fprintf(f,"long long %s = ",m_handle->name);
                else
                    fprintf(f,"long long = ");
                fprintf(f,"%lld",m_handle->value.longinteger);
                break;

            case ddf_body_t::DDF_FLOAT:
                if (m_handle->name)
                    fprintf(f,"double %s = ",m_handle->name);
                else
                    fprintf(f,"double = ");
                fprintf(f,"%.15f",m_handle->value.floating);
                break;

            case ddf_body_t::DDF_STRUCT:
                fprintf(f,"struct ");
                if (m_handle->name)
                    fprintf(f,"%s ",m_handle->name);
                putc('{',f);
                if (m_handle->value.children.count) {
                    putc('\n',f);
                    DDF child;
                    child.m_handle=m_handle->value.children.first;
                    while (child.m_handle) {
                        child.dump(f,indent+2);
                        child.m_handle=child.m_handle->next;
                    }
                }
                ddf_print_indent(f,indent);
                putc('}',f);
                break;

            case ddf_body_t::DDF_LIST:
                fprintf(f,"list");
                if (m_handle->name)
                    fprintf(f," %s",m_handle->name);
                fprintf(f,"[%lu] {",m_handle->value.children.count);
                if (m_handle->value.children.count) {
                    putc('\n',f);
                    DDF child;
                    child.m_handle=m_handle->value.children.first;
                    while (child.m_handle) {
                        child.dump(f,indent+2);
                        child.m_handle=child.m_handle->next;
                    }
                }
                ddf_print_indent(f,indent);
                putc('}',f);
                break;

            default:
                fprintf(f,"UNKNOWN -- WARNING: ILLEGAL VALUE");
        }
    }
    else
        fprintf(f,"nullptr");
    fprintf(f,";\n");
}

/*
    Serialization is now reliant on a line-centric, type-prefixed format.

    <URL-encoded name>|<space>|<typenum>|<space>|<type-specific>
    <space> := 0x20
    <typenum> := 0|1|2|3|4|5|7

    DDF_EMPTY:
        0
    DDF_STRING:
        1 URL-encoded string
    DDF_INT:
        2 32-bit integer
    DDF_FLOAT:
        3 fixed format double
    DDF_STRUCT:
        4 32-bit count of children
    DDF_LIST:
        5 32-bit count of children
    DDF_STRING_UNSAFE:
        6 URL-encoded string
    DDF_LONG:
        7 64-bit integer

    The distinction of unsafe strings allows for proper deserialization
    in languages that need to handle non-UTF8 strings differently.
*/

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

ostream& encode(ostream& os, const char* s)
{
    for (; *s; s++) {
        if (*s < 0x30 || *s > 0x7A) {
            os << '%';
            os << hexchar((unsigned char)*s >> 4);
            os << hexchar((unsigned char)*s & 0x0F);
        }
        else {
            os << *s;
        }
    }
    return os;
}

static bool is32bitSafe(long what)
{
    if (sizeof(what) <= 4) return true;
    unsigned long uWhat = (what < 0) ? -what : what;
    unsigned long upperOfuWhat = uWhat >> 31;

    return (0 == upperOfuWhat);
}

static bool is64bitSafe(long long what)
{
    if (sizeof(what) <= 8) return true;
    unsigned long long uWhat = (what < 0) ? -what : what;
    unsigned long long upperOfuWhat = uWhat >> 63;

    return (0 == upperOfuWhat);
}

void serialize(ddf_body_t* p, ostream& os)
{
    if (p) {
        if (p->name) {
            encode(os, p->name);
        } else {
            os << '.';
        }
        os << ' ';

        switch (p->type) {
            case ddf_body_t::DDF_EMPTY:
                os << ddf_body_t::DDF_EMPTY << endl;
                break;

            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                os << p->type;
                if (p->value.string) {
                    os << ' ';
                    encode(os, p->value.string);
                }
                os << endl;
                break;

            case ddf_body_t::DDF_INT:
                if (!is32bitSafe(p->value.integer))
                    throw range_error("Integer Overflow");
                os << ddf_body_t::DDF_INT << ' ' << p->value.integer << endl;
                break;

            case ddf_body_t::DDF_LONG:
                if (!is64bitSafe(p->value.longinteger))
                    throw range_error("Integer Overflow");
                os << ddf_body_t::DDF_LONG << ' ' << p->value.longinteger << endl;
                break;

            case ddf_body_t::DDF_FLOAT:
                os << ddf_body_t::DDF_FLOAT << ' ' << setprecision(15) << fixed
                    << p->value.floating << dec << endl;
                break;

            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
            {
                os << p->type << ' ' << p->value.children.count << endl;
                ddf_body_t* child = p->value.children.first;
                while (child) {
                    serialize(child, os);
                    child = child->next;
                }
                break;
            }

            default:
                break;
        }
    }
}

// The stream insertion will work for any ostream-based object.

SHIBSP_API ostream& shibsp::operator<<(ostream& os, const DDF& obj)
{
    os.precision(15);
    serialize(obj.m_handle, os);
    return os;
}

DDF deserialize(istream& is)    
{
    string line;
    getline(is, line);
    if (!is) {
        return DDF();
    }

    istringstream source(line);

    // Name is first.
    string name;
    source >> name;
    if (!source || name.empty()) {
        return DDF();
    }

    DDF obj(nullptr);
    if (name != ".") {
        if (name.find('%') != string::npos) {
            char* dup = strdup(name.c_str());
            if (!dup) {
                return obj;
            }
            // Walk the string and decode any %XX sequences.
            int x,y;
            for(x=0,y=0; dup[y]; ++x,++y) {
                if((dup[x] = dup[y]) == '%' && isxdigit(dup[y+1]) && isxdigit(dup[y+2])) {
                    dup[x] = x2c(&dup[y+1]);
                    y+=2;
                }
            }
            dup[x] = '\0';

            obj.name(dup);
            free(dup);
        }
        else {
            obj.name(name.c_str());
        }
    }

    // Type is next and should match enums.
    short type;
    source >> type;
    if (!source) {
        return obj;
    }
    
    switch (type) {
        case ddf_body_t::DDF_EMPTY:
            // Nothing to do, it's already empty.
            return obj;

        case ddf_body_t::DDF_STRING:
        case ddf_body_t::DDF_STRING_UNSAFE:
            {
                string valstr;
                source >> valstr;
                if (!source || valstr.empty()) {
                    if (type == ddf_body_t::DDF_STRING) {
                        obj.string(valstr.c_str());
                    }
                    else {
                        obj.unsafe_string(valstr.c_str());
                    }
                    return obj;
                }
                char* dup = strdup(valstr.c_str());
                if (!dup) {
                    return obj;
                }

                // Walk the string and decode any %XX sequences.
                int x,y;
                for(x=0,y=0; dup[y]; ++x,++y) {
                    if((dup[x] = dup[y]) == '%' && isxdigit(dup[y+1]) && isxdigit(dup[y+2])) {
                        dup[x] = x2c(&dup[y+1]);
                        y+=2;
                    }
                }
                dup[x] = '\0';

                // Store without extra copy.
                obj.string(dup, false, type == ddf_body_t::DDF_STRING);
            }
            break;

        case ddf_body_t::DDF_INT:
            {
                long value = 0;
                source >> value;
                if (!source) {
                    return obj;
                }
                obj.integer(value);
            }
            break;

        case ddf_body_t::DDF_LONG:
            {
                long long value = 0;
                source >> value;
                if (!source) {
                    return obj;
                }
                obj.longinteger(value);
            }
            break;

        case ddf_body_t::DDF_FLOAT:
            {
                double value = 0; 
                source >> fixed >> value >> dec;
                if (!source) {
                    return obj;
                }
                obj.floating(value);
            }
            break;

        case ddf_body_t::DDF_STRUCT:
            {
                long count = 0;
                source >> count;
                if (!source) {
                    return obj;
                }
                obj.structure();
                for (; count; --count) {
                    DDF child = deserialize(is);
                    if (!child.isnull()) {
                        obj.add(child);
                    } else {
                        break;
                    }
                }
            }
            break;

        case ddf_body_t::DDF_LIST:
            {
                long count = 0;
                source >> count;
                if (!source) {
                    return obj;
                }
                obj.list();
                for (; count; --count) {
                    DDF child = deserialize(is);
                    if (!child.isnull()) {
                        obj.add(child);
                    } else {
                        break;
                    }
                }
            }
            break;

        default:
            break;
    }

    return obj;
}

SHIBSP_API istream& shibsp::operator>>(istream& is, DDF& obj)
{
    obj.destroy();
    obj = deserialize(is);
    return is;
}
