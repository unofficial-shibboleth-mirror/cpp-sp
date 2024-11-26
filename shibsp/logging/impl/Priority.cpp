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

#include <shibsp/logging/Priority.h>

#include <cstdlib>
#include <stdexcept>

using namespace shibsp;
using namespace std;

namespace {
	const string names[7] = {
		"CRIT", "ERROR", "WARN", "INFO", "DEBUG", "NOTSET", "UNKNOWN"
	};
}

const string& Priority::getPriorityName(int priority) throw() {
		
	priority++;
	priority /= 100;
	return names[((priority < 0) || (priority > 5)) ? 5 : priority];
}

Priority::Value Priority::getPriorityValue(const string& priorityName) {
	Priority::Value value = -1;

	for (unsigned int i = 0; i < 7; i++) {
		if (priorityName == names[i]) {
			value = i * 100;
			break;
		}
	}

	if (value == -1) {
		char* endPointer;
		value = strtoul(priorityName.c_str(), &endPointer, 10);
		if (*endPointer != 0) {
			throw invalid_argument(string("unknown priority name: '") + priorityName + "'");
		}
	}

	return value;
}
