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
 * @file shibsp/remoting/ddf.h
 * 
 * C++ DDF abstraction for interpretive RPC
 */

#ifndef __ddf_h__
#define __ddf_h__

#include <shibsp/base.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace shibsp {

    /**
     * DDF objects are implemented with a handle-body idiom and require explicit
     * destruction in order to allow stack objects to be freely mixed in structures
     * with heap objects. When stack objects leave scope, only the handle is freed.
     * Copying and assigning handle objects is a constant time operation equivalent
     * to a single pointer assignment, handled by compiler-generated behavior.
     * 
     * This code long predates modern C++, and may eventually be updated but for the
     * moment, it does not provide the automatic memory mamagement that would be
     * expected from such a library.
     */
    class SHIBSP_API DDF
    {
    public:
        /// @cond OFF
        // constructors
        DDF();
        DDF(const char* n);
        DDF(const char* n, const char* val, bool safe=true);
        DDF(const char* n, long val);
        DDF(const char* n, long long val);
        DDF(const char* n, double val);
    
        DDF& destroy();         // deep destructor
        DDF copy() const;       // deep copy routine
    
        // property accessors
        const char* name() const;
        DDF& name(const char* n);
        DDF& name(const std::string& n);
    
        // basic type checking
        bool isnull() const;
        bool isempty() const;
        bool isstring() const;
        bool isint() const;
        bool islong() const;
        bool isfloat() const;
        bool isstruct() const;
        bool islist() const;
    
        // type conversion and value extraction
        const char* string() const;     // legal for str
        long        integer() const;    // legal for all types
        long long   longinteger() const;    // legal for all types
        double      floating() const;   // legal for float
    
        // string helper methods
        size_t strlen() const;
        bool operator==(const char* s) const;
    
        // destructive node conversion methods
        DDF& empty();
        DDF& string(char* val, bool copyit=true, bool safe=true);
        DDF& string(const char* val);
        DDF& string(const std::string& val);
        DDF& unsafe_string(const char* val);
        DDF& string(long val);
        DDF& string(double val);
        DDF& integer(long val);
        DDF& integer(const char* val);
        DDF& longinteger(long long val);
        DDF& longinteger(const char* val);
        DDF& floating(double val);
        DDF& floating(const char* val);
        DDF& structure();
        DDF& list();
    
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
        DDF operator[](const char* path) const;
    
        // named member access/creation
        DDF addmember(const char* path);
        DDF getmember(const char* path) const;
    
        // debugging
        void dump(std::FILE* f=nullptr, int indent=0) const;
    
        // serialization functions need private access
        friend SHIBSP_API std::ostream& operator<<(std::ostream& os, const DDF& obj);
        friend SHIBSP_API std::istream& operator>>(std::istream& is, DDF& obj);
        /// @endcond
    private:
        struct ddf_body_t* m_handle;
    };

    /**
     * Serializes a DDF object to a stream.
     * 
     * @param os    output stream
     * @param obj   DDF object to serialize
     * @return reference to the output stream
     */    
    SHIBSP_API std::ostream& operator<<(std::ostream& os, const DDF& obj);

    /**
     * Reconstitutes a DDF object from a stream.
     * 
     * @param is    input stream
     * @param obj   DDF object to reconstitute
     * @return reference to the input stream
     */
    SHIBSP_API std::istream& operator>>(std::istream& is, DDF& obj);
    
    /**
     * A "smart pointer" for disposing of DDF objects when they leave scope.
     */
    class SHIBSP_API DDFJanitor
    {
    public:
        /**
         * Assume ownership of the supplied object.
         * 
         * @param obj object to take ownership of
         */
        DDFJanitor(DDF& obj) : m_obj(obj) {}

        /**
         * Free the owned object unless previously released.
         */
        ~DDFJanitor() { m_obj.destroy(); }

        /**
         * Release ownership of the stored object and return it.
         * 
         * @return the stored object, now owned by caller
         */
        DDF release() { DDF ret = m_obj; m_obj = DDF(); return ret; }
        
    private:
        DDF& m_obj;
        DDFJanitor(const DDFJanitor&);
        DDFJanitor& operator=(const DDFJanitor&);
    };

}

#endif // __ddf_h__
