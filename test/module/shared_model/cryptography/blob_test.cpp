/**
 * Copyright Soramitsu Co., Ltd. 2017 All Rights Reserved.
 * http://soramitsu.co.jp
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

#include "gtest/gtest.h"
#include "cryptography/blob.hpp"

using namespace shared_model::crypto;

/**
 * @given arbitrary string and known its hex representation
 * @when conversion of this string to hex is done
 * @then conversion is done right
 */
TEST(BlobTest, HexConversionTest){
  auto data = "Hello World";
  Blob blob(data);
  auto hex = blob.hex();
  ASSERT_EQ("48656c6c6f20576f726c64", hex);
}
