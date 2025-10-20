/*
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
 * util/ISOParserTests.cpp
 *
 * Unit tests for ISO Date/Time/Duration parsing.
 */

#include "util/Misc.h"

#include <boost/test/unit_test.hpp>

using namespace shibsp;
using namespace std;

BOOST_AUTO_TEST_CASE(DurationTests)
{
    BOOST_CHECK_EQUAL(parseISODuration("Foo"), 0);
    BOOST_CHECK_EQUAL(parseISODuration("PT10S"), 10);
    BOOST_CHECK_EQUAL(parseISODuration("PT10M"), 10 * 60);
    BOOST_CHECK_EQUAL(parseISODuration("PT10H"), 10 * 60 * 60);
    BOOST_CHECK_EQUAL(parseISODuration("P1D"), 24 * 60 * 60);
    BOOST_CHECK_EQUAL(parseISODuration("P1Y"), 31556926);

    BOOST_CHECK_EQUAL(parseISODuration("P1DT1H1M1S"), 24 * 60 * 60 + 60 * 60 + 60 + 1);

    BOOST_CHECK_EQUAL(parseISODuration("PT10H5M30S"), 10 * 60 * 60 + 5 * 60 + 30);
}
