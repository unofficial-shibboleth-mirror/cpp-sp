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
 * @file shibsp/attribute/AttributeConfiguration.h
 * 
 * Interface to settings and functionality for attribute data manipulation.
 */

#ifndef __shibsp_attrconfig_h__
#define __shibsp_attrconfig_h__

#include <shibsp/util/PropertySet.h>

#include <memory>
#include <set>

#include <boost/property_tree/ptree_fwd.hpp>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex_fwd.hpp>
namespace regexp = boost;
#else
# include <regex>
namespace regexp = std;
#endif

namespace shibsp {

    class SHIBSP_API DDF;
    class SHIBSP_API Session;
    class SHIBSP_API SPRequest;

    /**
     * Interface to settings and functionality for attribute data manipulation.
     * 
     * <p>This isn't an especially coherent interface but it centralizes config
     * settings for a lot of what used to be scattered around the code base.</p>
     */
    class SHIBSP_API AttributeConfiguration : public virtual PropertySet
    {
        MAKE_NONCOPYABLE(AttributeConfiguration);
    protected:
    AttributeConfiguration();

    public:
        virtual ~AttributeConfiguration();

        /** Used in ACL implementations to enforce legacy authnContextClassRef rule. */
        static const char LEGACY_CLASSREF_ATTRIBUTE_PROP_NAME[];
        static const char LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT[];

        /** Used in ACL implementation to enforce legacy time-since-authn rule. */
        static const char LEGACY_AUTHTIME_ATTRIBUTE_PROP_NAME[];
        static const char LEGACY_AUTHTIME_ATTRIBUTE_PROP_DEFAULT[];

        /** Delimiter to separate multiple attribute values in exported variables. */
        static const char VALUE_DELIMITER_PROP_NAME[];
        static const char VALUE_DELIMITER_PROP_DEFAULT[];

        /**
         * Post-process a collection of attributes and values from the hub for use by agent code.
         * 
         * <p>This handles serialization of data not already in simple "string" form so that
         * subsequent usage is simpler. In particular it allows scoped data to be recombined with
         * an agent-controlled delimiter.</p>
         * 
         * <p>If true is returned, the resulting object must be a list. Each element must
         * also be a list with a non-empty name and at least one non-empty string value.
         * Any non-conforming data must be removed from the object.</p>
         * 
         * @param attributes a list object containing the attributes in hub-supplied format
         * 
         * @return true iff at least one attribute exists after processing and the data is in
         *  the expected form
         */
        virtual bool processAttributes(DDF& attributes) const=0;

        /**
         * Gets whether an attribute is configured to be "case sensitive" for value comparison
         * purposes.
         * 
         * @param attributeID the ID of the attribute to check
         * 
         * @return true iff the attribute's values should be handled with case sensitivity
         */
        virtual bool isCaseSensitive(const char* attributeID) const=0;

        /**
         * "Clears" any headers controlled by the agent to reserve them for trusted attribute export.
         * 
         * <p>This method typically operates only when it detects the request will include header
         * support, which is strongly discouraged.</p>
         * 
         * @param request request to "clear"
         */
        virtual void clearHeaders(SPRequest& request) const=0;

        /**
         * Exports data from the session into variables/headers in the supplied request.
         * 
         * @param request request to export into
         * @param locked session to pull data from
         */
        virtual void exportAttributes(SPRequest& request, const Session& session) const=0;

        /**
         * Tests whether a given attribute in a session contains a matching value.
         * 
         * <p>It is an internal implementation detail as to the relevance of case to this
         * comparison.</p>
         * 
         * @param session locked session to pull from
         * @param attributeId the attribute to check
         * @param value the value to check for
         * 
         * @return true iff the value "matched"
         */
        virtual bool hasMatchingValue(const Session& session, const char* attributeId, const char* value) const=0;

        /**
         * Tests whether a given attribute in a session contains a matching value from a set.
         * 
         * <p>It is an internal implementation detail as to the relevance of case to this
         * comparison.</p>
         * 
         * @param session locked session to pull from
         * @param attributeId the attribute to check
         * @param values the set of values to check for
         * 
         * @return true iff at least one value "matched"
         */
        virtual bool hasMatchingValue(
            const Session& session, const char* attributeId, const std::set<std::string>& values
            ) const=0;

        /**
         * Tests whether a given attribute in a session contains a value matching a supplied
         * regular expression.
         * 
         * @param session locked session to pull from
         * @param attributeId the attribute to check
         * @param values the set of values to check for
         * 
         * @return true iff at least one value "matched"
         */
        virtual bool hasMatchingValue(
            const Session& session, const char* attributeId, const regexp::regex& expression
            ) const=0;

        /**
         * Create a new AttributeConfiguration based on the supplied configuration file.
         * 
         * @param pathname  configuration file
         * 
         * @return the corresponding AttributeConfiguration
         */
        static std::unique_ptr<AttributeConfiguration> newAttributeConfiguration(const char* pathname);

        /**
         * Create a new AttributeConfiguration based on an existing ptree.
         * 
         * @param pt  property tree
         * 
         * @return the corresponding AttributeConfiguration
         */
        static std::unique_ptr<AttributeConfiguration> newAttributeConfiguration(const boost::property_tree::ptree& pt);
    };

};

#endif /* __shibsp_attrconfig_h__ */
