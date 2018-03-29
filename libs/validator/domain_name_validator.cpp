/**
 * Copyright AltPlus Inc., Ltd. 2017 All Rights Reserved.
 * http://en.altplus.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <boost/spirit/include/qi.hpp>
#include <regex>

#include "validator/domain_name_validator.hpp"

namespace validator {
  bool isValidDomainName(const std::string &str) {
    return std::regex_match(
        str,
        std::regex(
            R"#(^([a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$)#"));
  }
}  // namespace validator
