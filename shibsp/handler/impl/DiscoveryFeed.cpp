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
 * DiscoveryFeed.cpp
 *
 * Handler for generating a JSON discovery feed based on metadata.
 */

#include "internal.h"
#include "AgentConfig.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "util/PathResolver.h"

#include <ctime>
#include <fstream>
#include <sstream>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/Threads.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251)
#endif

    class SHIBSP_DLLLOCAL Blocker : public DOMNodeFilter
    {
    public:
        FilterAction acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL Blocker g_Blocker;

    class SHIBSP_API DiscoveryFeed : public AbstractHandler, public RemotedHandler
    {
    public:
        DiscoveryFeed(const DOMElement* e, const char* appId);
        virtual ~DiscoveryFeed();

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

    private:
        void feedToFile(const Application& application, string& cacheTag) const;
        void feedToStream(const Application& application, string& cacheTag, ostream& os) const;

        string m_dir;
        bool m_cacheToClient;
#ifndef SHIBSP_LITE
        // Application-specific queues of feed files, linked to the last time of "access".
        // The key to the map is the application's "hash" code, not the ID itself.
        // Each filename is also a cache tag.
        typedef queue< pair<string, time_t> > feedqueue_t;
        mutable map<string,feedqueue_t> m_feedQueues;
        scoped_ptr<Mutex> m_feedLock;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL DiscoveryFeedFactory(const pair<const DOMElement*,const char*>& p, bool)
    {
        return new DiscoveryFeed(p.first, p.second);
    }

};

DiscoveryFeed::DiscoveryFeed(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT ".Handler.DiscoveryFeed"), &g_Blocker), m_cacheToClient(false)
{
    pair<bool,const char*> prop = getString("Location");
    if (!prop.first)
        throw ConfigurationException("DiscoveryFeed handler requires Location property.");
    string address(appId);
    address += prop.second;
    setAddress(address.c_str());

    pair<bool,bool> flag = getBool("cacheToClient");
    m_cacheToClient = flag.first && flag.second;
    flag = getBool("cacheToDisk");
    if (!flag.first || flag.second) {
        prop = getString("dir");
        if (prop.first)
            m_dir = prop.second;
        AgentConfig::getConfig().getPathResolver().resolve(m_dir, PathResolver::SHIBSP_CACHE_FILE);
        m_log.info("feed files will be cached in %s", m_dir.c_str());
#ifndef SHIBSP_LITE
        m_feedLock.reset(Mutex::create());
#endif
    }
}

DiscoveryFeed::~DiscoveryFeed()
{
#ifndef SHIBSP_LITE
    if (m_feedLock.get()) {
        // Remove any files unused for more than a couple of minutes.
        time_t now = time(nullptr);
        for (map<string, feedqueue_t>::iterator i = m_feedQueues.begin(); i != m_feedQueues.end(); ++i) {
            while (!i->second.empty() && now - i->second.front().second > 60) {
                string fname = m_dir + '/' + i->first + '_' + i->second.front().first + ".json";
                remove(fname.c_str());
                i->second.pop();
            }
        }
    }
#endif
}

pair<bool,long> DiscoveryFeed::run(SPRequest& request, bool isHandler) const
{
    try {
        SPConfig& conf = SPConfig::getConfig();

        string s;
        if (m_cacheToClient) {
            s = request.getHeader("If-None-Match");
        }

        if (conf.isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            if (m_dir.empty()) {
                // The feed is directly returned.
                stringstream buf;
                feedToStream(request.getApplication(), s, buf);
                if (!s.empty()) {
                    if (m_cacheToClient) {
                        string etag = '"' + s + '"';
                        request.setResponseHeader("ETag", etag.c_str());
                    }
                    request.setContentType("application/json; charset=UTF-8");
                    return make_pair(true, request.sendResponse(buf));
                }
            }
            else {
                // Indirect the feed through a file.
                feedToFile(request.getApplication(), s);
            }
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = DDF(m_address.c_str());
            in.addmember("application_id").string(request.getApplication().getId());
            if (!s.empty())
                in.addmember("cache_tag").string(s.c_str());
            DDFJanitor jin(in), jout(out);
            out = send(request, in);
            s.erase();
            if (m_dir.empty()) {
                // The cache tag and feed are in the response struct.
                if (m_cacheToClient && out["cache_tag"].string()) {
                    string etag = string("\"") + out["cache_tag"].string() + '"';
                    request.setResponseHeader("ETag", etag.c_str());
                }
                if (out["feed"].string()) {
                    istringstream buf(out["feed"].string());
                    request.setContentType("application/json; charset=UTF-8");
                    return make_pair(true, request.sendResponse(buf));
                }
                throw ConfigurationException("Discovery feed was empty.");
            }
            else {
                // The response object is a string containing the cache tag.
                if (out.isstring() && out.string())
                    s = out.string();
            }
        }

        if (s.empty()) {
            m_log.debug("client's cache tag matches our feed");
            istringstream msg("Not Modified");
            return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED));
        }

        string fname = m_dir + '/' + request.getApplication().getHash() + '_' + s + ".json";
        ifstream feed(fname.c_str());
        if (!feed)
            throw ConfigurationException("Unable to access cached feed in ($1).", params(1,fname.c_str()));
        if (m_cacheToClient) {
            string etag = '"' + s + '"';
            request.setResponseHeader("ETag", etag.c_str());
        }
        request.setContentType("application/json; charset=UTF-8");
        return make_pair(true, request.sendResponse(feed));
    }
    catch (std::exception& ex) {
        request.log(Priority::SHIB_ERROR, string("error while processing request:") + ex.what());
        istringstream msg("Discovery Request Failed");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void DiscoveryFeed::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for discovery feed request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for discovery feed request, deleted?");
    }

    string cacheTag;
    if (in["cache_tag"].string())
        cacheTag = in["cache_tag"].string();

    DDF ret(nullptr);
    DDFJanitor jout(ret);

    if (!m_dir.empty()) {
        // We're relaying the feed through a file.
        feedToFile(*app, cacheTag);
        if (!cacheTag.empty())
            ret.string(cacheTag.c_str());
    }
    else {
        // We're relaying the feed directly.
        ostringstream os;
        feedToStream(*app, cacheTag, os);
        if (!cacheTag.empty())
            ret.addmember("cache_tag").string(cacheTag.c_str());
        string feed = os.str();
        if (!feed.empty())
            ret.addmember("feed").string(feed.c_str());
    }
    out << ret;
}

void DiscoveryFeed::feedToFile(const Application& application, string& cacheTag) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing discovery feed request");

    DiscoverableMetadataProvider* m = dynamic_cast<DiscoverableMetadataProvider*>(application.getMetadataProvider(false));
    if (!m)
        m_log.warn("MetadataProvider missing or does not support discovery feed");
    Locker locker(m);
    string feedTag = m ? m->getCacheTag() : "empty";
    if (cacheTag == ('"' + feedTag + '"')) {
        // The client already has the same feed we do.
        m_log.debug("client's cache tag matches our feed (%s)", feedTag.c_str());
        cacheTag.erase();   // clear the tag to signal no change
        return;
    }

    cacheTag = feedTag;

    // The client is out of date or not caching, so we need to see if our copy is good.
    Lock lock(m_feedLock);
    time_t now = time(nullptr);

    // Clean up as many old files as it's safe to do.
    feedqueue_t& q = m_feedQueues[application.getHash()];
    while (q.size() > 1 && (now - q.front().second > 60)) {
        string fname = m_dir + '/' + application.getHash() + '_' + q.front().first + ".json";
        remove(fname.c_str());
        q.pop();
    }

    if (q.empty() || q.back().first != feedTag) {
        // We're out of date.
        string fname = m_dir + '/' + application.getHash() + '_' + feedTag + ".json";
        ofstream ofile(fname.c_str());
        if (!ofile)
            throw ConfigurationException("Unable to create feed in ($1).", params(1,fname.c_str()));
        bool first = true;
        if (m)
            m->outputFeed(ofile, first);
        else
            ofile << "[\n]";
        ofile.close();
        q.push(make_pair(feedTag, now));
    }
    else {
        // Update the back of the queue.
        q.back().second = now;
    }
#else
    throw ConfigurationException("Build does not support discovery feed.");
#endif
}

void DiscoveryFeed::feedToStream(const Application& application, string& cacheTag, ostream& os) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing discovery feed request");

    DiscoverableMetadataProvider* m = dynamic_cast<DiscoverableMetadataProvider*>(application.getMetadataProvider(false));
    if (!m)
        m_log.warn("MetadataProvider missing or does not support discovery feed");
    Locker locker(m);
    string feedTag = m ? m->getCacheTag() : "empty";
    if (cacheTag == ('"' + feedTag + '"')) {
        // The client already has the same feed we do.
        m_log.debug("client's cache tag matches our feed (%s)", feedTag.c_str());
        cacheTag.erase();   // clear the tag to signal no change
        return;
    }

    cacheTag = feedTag;
    bool first = true;
    if (m)
        m->outputFeed(os, first);
    else
        os << "[\n]";
#else
    throw ConfigurationException("Build does not support discovery feed.");
#endif
}
