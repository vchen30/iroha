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
#ifndef IROHA_QUERY_EXECUTION_HPP
#define IROHA_QUERY_EXECUTION_HPP

#include "model/query.hpp"
#include "model/query_response.hpp"

#include "model/queries/get_account.hpp"
#include "model/queries/get_account_assets.hpp"
#include "model/queries/get_account_detail.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/queries/get_signatories.hpp"
#include "model/queries/get_transactions.hpp"

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/wsv_query.hpp"

namespace shared_model {
  namespace interface {
    class QueryResponse;
    class Query;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace model {

    /**
     * Converting business objects to protobuf and vice versa
     */
    class QueryProcessingFactory {
     public:
      /**
       * Execute and validate query.
       *
       * @param query
       * @return
       */
      std::shared_ptr<shared_model::interface::QueryResponse> execute(
          const shared_model::interface::Query &query);
      /**
       *
       * @param wsvQuery
       * @param blockQuery
       */
      QueryProcessingFactory(std::shared_ptr<ametsuchi::WsvQuery> wsvQuery,
                             std::shared_ptr<ametsuchi::BlockQuery> blockQuery);

     private:
      bool validate(
          const shared_model::interface::Query &query,
          const shared_model::interface::GetAssetInfo &get_asset_info);

      bool validate(const shared_model::interface::Query &query,
                    const shared_model::interface::GetRoles &get_roles);

      bool validate(const shared_model::interface::Query &query,
                    const shared_model::interface::GetRolePermissions
                        &get_role_permissions);

      bool validate(
          const shared_model::interface::Query &query,
          const shared_model::interface::GetAccountAssets &get_account_assets);

      bool validate(const shared_model::interface::Query &query,
                    const shared_model::interface::GetAccount &get_account);

      bool validate(
          const shared_model::interface::Query &query,
          const shared_model::interface::GetSignatories &get_signatories);

      bool validate(const shared_model::interface::Query &query,
                    const shared_model::interface::GetAccountTransactions
                        &get_account_transactions);

      bool validate(const shared_model::interface::Query &query,
                    const shared_model::interface::GetAccountAssetTransactions
                        &get_account_asset_transactions);

      bool validate(
          const shared_model::interface::Query &query,
          const shared_model::interface::GetAccountDetail &get_account_detail);

      bool validate(
          const shared_model::interface::Query &query,
          const shared_model::interface::GetTransactions &get_transactions);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetAssetInfo(
          const shared_model::interface::GetAssetInfo &get_asset_info,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse> executeGetRoles(
          const shared_model::interface::GetRoles &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetRolePermissions(
          const shared_model::interface::GetRolePermissions &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetAccountAssets(
          const shared_model::interface::GetAccountAssets &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetAccountDetail(
          const shared_model::interface::GetAccountDetail &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse> executeGetAccount(
          const shared_model::interface::GetAccount &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetSignatories(
          const shared_model::interface::GetSignatories &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetAccountAssetTransactions(
          const shared_model::interface::GetAccountAssetTransactions &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetAccountTransactions(
          const shared_model::interface::GetAccountTransactions &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<shared_model::interface::QueryResponse>
      executeGetTransactions(
          const shared_model::interface::GetTransactions &query,
          const shared_model::interface::types::HashType &hash);

      std::shared_ptr<ametsuchi::WsvQuery> _wsvQuery;
      std::shared_ptr<ametsuchi::BlockQuery> _blockQuery;
    };

  }  // namespace model
}  // namespace iroha

#endif  // IROHA_QUERY_EXECUTION_HPP
