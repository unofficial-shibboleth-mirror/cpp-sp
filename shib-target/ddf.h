/*
 *  Copyright 2001-2005 Internet2
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

/*
 * ddf.h - C++ DDF abstraction for interpretive RPC
 *
 * Created by:  Scott Cantor and Tom Sanfilippo, OSU
 *
 * $Id$
 */

#ifndef __ddf_h__
#define __ddf_h__

#include <cstdio>
#include <iostream>

#ifdef WIN32
# ifndef SHIBTARGET_EXPORTS
#  define SHIBTARGET_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIBTARGET_EXPORTS
#endif

/**
 * DDF objects are implemented with a handle-body idiom and require explicit
 * destruction in order to allow stack objects to be freely mixed in structures
 * with heap objects. When stack objects leave scope, only the handle is freed.
 * Copying and assigning handle objects is a constant time operation equivalent
 * to a single pointer assignment, handled by compiler-generated behavior.
 */

namespace shibtarget {

class SHIBTARGET_EXPORTS DDF
{
public:
    // constructors
    DDF() : m_handle(NULL) {}
    DDF(const char* n);
    DDF(const char* n, const char* val);
    DDF(const char* n, long val);
    DDF(const char* n, double val);
    DDF(const char* n, void* val);

    DDF& destroy();         // deep destructor
    DDF copy() const;       // deep copy routine

    // property accessors
    const char* name() const;           DDF& name(const char* n);

    // basic type checking
    bool isnull() const;
    bool isempty() const;
    bool isstring() const;
    bool isint() const;
    bool isfloat() const;
    bool isstruct() const;
    bool islist() const;
    bool ispointer() const;

    // type conversion and value extraction
    const char* string() const;     // legal for str
    long        integer() const;    // legal for all types
    double      floating() const;   // legal for float
    void*       pointer() const;    // legal for pointer

    // string helper methods
    size_t strlen() const;
    bool operator==(const char* s) const;

    // destructive node conversion methods
    DDF& empty();
    DDF& string(const char* val);
    DDF& string(long val);
    DDF& string(double val);
    DDF& integer(long val);
    DDF& integer(const char* val);
    DDF& floating(double val);
    DDF& floating(const char* val);
    DDF& structure();
    DDF& list();
    DDF& pointer(void* val);

    // list/struct methods
    DDF& add(DDF& child);
    DDF& addbefore(DDF& child, DDF& before);
    DDF& addafter(DDF& child, DDF& after);
    void swap(DDF& arg);
    DDF& remove();

    // C-style iterators
    DDF parent() const;
    DDF first();
    DDF next();
    DDF last();
    DDF previous();
    
    // indexed operators
    DDF operator[](unsigned long index) const;
    DDF operator[](const char* path) const { return getmember(path); }

    // named member access/creation
    DDF addmember(const char* path);
    DDF getmember(const char* path) const;

    // debugging
    void dump(FILE* f=NULL, int indent=0) const;

    // serialization functions need private access
    friend SHIBTARGET_EXPORTS std::ostream& operator<<(std::ostream& os, const DDF& obj);
    friend SHIBTARGET_EXPORTS std::istream& operator>>(std::istream& is, DDF& obj);
private:
    struct ddf_body_t* m_handle;
};

// XML/WDDX serialization
SHIBTARGET_EXPORTS std::ostream& operator<<(std::ostream& os, const DDF& obj);
SHIBTARGET_EXPORTS std::istream& operator>>(std::istream& is, DDF& obj);

/**
 * A "smart pointer" for disposing of DDF objects when they leave scope.
 */
class SHIBTARGET_EXPORTS DDFJanitor
{
public:
    DDFJanitor(DDF& obj) : m_obj(obj) {}
    ~DDFJanitor() { m_obj.destroy(); }
private:
    DDF& m_obj;
    DDFJanitor(const DDFJanitor&);
    DDFJanitor& operator=(const DDFJanitor&);
};

}

#endif // __ddf_h__
