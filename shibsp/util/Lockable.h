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
 * @file shibsp/util/Lockable.h
 * 
 * Interfaces for C++ locking template compatibility.
 */

#ifndef __shibsp_lockable_h__
#define __shibsp_lockable_h__

#include <shibsp/base.h>

namespace shibsp {

    /**
     * BasicLockable semantics for exclusive locking.
     */
    class SHIBSP_API BasicLockable
    {
    public:
        virtual void lock()=0;
        virtual bool try_lock()=0;
        virtual void unlock()=0;
    };

    /**
     * A class supplying a BasicLockable implementation as a no-op.
     */
    class SHIBSP_API NoOpBasicLockable : public virtual BasicLockable
    {
    public:
        void lock() {}
        bool try_lock() { return true; }
        void unlock() {}
    };

    /**
     * SharedLockable semantics for shared locking.
     */
    class SHIBSP_API SharedLockable
    {
    public:
        virtual void lock_shared()=0;
        virtual bool try_lock_shared()=0;
        virtual void unlock_shared()=0;
    };

    /**
     * A class supplying a SharedLockable implementation as a no-op.
     */
    class SHIBSP_API NoOpSharedLockable : public virtual SharedLockable
    {
    public:
        void lock_shared() {}
        bool try_lock_shared() { return true; }
        void unlock_shared() {}
    };

};

#endif /* __shibsp_lockable_h__ */
