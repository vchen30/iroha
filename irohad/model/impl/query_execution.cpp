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

#include "model/query_execution.hpp"
#include <boost/algorithm/string.hpp>
#include <rxcpp/rx-observable.hpp>
#include <utility>
#include "builders/protobuf/builder_templates/query_response_template.hpp"
#include "common/visitor.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "model/execution/common_executor.hpp"
#include "model/permissions.hpp"
#include "model/queries/responses/account_assets_response.hpp"
#include "model/queries/responses/account_detail_response.hpp"
#include "model/queries/responses/account_response.hpp"
#include "model/queries/responses/asset_response.hpp"
#include "model/queries/responses/error_response.hpp"
#include "model/queries/responses/roles_response.hpp"
#include "model/queries/responses/signatories_response.hpp"
#include "model/queries/responses/transactions_response.hpp"
#include "model/sha3_hash.hpp"

using namespace iroha::model;
using namespace iroha::ametsuchi;

template <class T>
using w = shared_model::detail::PolymorphicWrapper<T>;

using QueryResponseBuilder =
    shared_model::proto::TemplateQueryResponseBuilder<>;

QueryProcessingFactory::QueryProcessingFactory(
    std::shared_ptr<ametsuchi::WsvQuery> wsvQuery,
    std::shared_ptr<ametsuchi::BlockQuery> blockQuery)
    : _wsvQuery(std::move(wsvQuery)), _blockQuery(std::move(blockQuery)) {}

std::string getDomainFromName(const std::string &account_id) {
  std::vector<std::string> res;
  boost::split(res, account_id, boost::is_any_of("@"));
  return res.size() > 1 ? res.at(1) : "";
}

template <class T>
std::shared_ptr<shared_model::interface::QueryResponse> build_error(
    const shared_model::interface::types::HashType &hash) {
  auto response =
      QueryResponseBuilder().queryHash(hash).errorQueryResponse<T>().build();
  return clone(response);
}

bool hasQueryPermission(const std::string &creator,
                        const std::string &target_account,
                        WsvQuery &wsv_query,
                        const std::string &indiv_permission_id,
                        const std::string &all_permission_id,
                        const std::string &domain_permission_id) {
  auto perms_set = getAccountPermissions(creator, wsv_query);
  return
      // 1. Creator has grant permission from other user
      (creator != target_account
       and wsv_query.hasAccountGrantablePermission(
               creator, target_account, indiv_permission_id))
      or  // ----- Creator has role permission ---------
      (perms_set
       and (
               // 2. Creator want to query his account, must have role
               // permission
               (creator == target_account
                and accountHasPermission(perms_set.value(),
                                         indiv_permission_id))
               or  // 3. Creator has global permission to get any account
               (accountHasPermission(perms_set.value(),
                                     all_permission_id))
               or  // 4. Creator has domain permission
               (getDomainFromName(creator) == getDomainFromName(target_account)
                and accountHasPermission(perms_set.value(),
                                         domain_permission_id))));
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAssetInfo &get_asset_info) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return checkAccountRolePermission(
      query.creatorAccountId(), *_wsvQuery, can_read_assets);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetRoles &get_roles) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return checkAccountRolePermission(
      query.creatorAccountId(), *_wsvQuery, can_get_roles);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetRolePermissions &get_role_permissions) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return checkAccountRolePermission(
      query.creatorAccountId(), *_wsvQuery, can_get_roles);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAccount &get_account) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_account.accountId(),
                            *_wsvQuery,
                            can_get_my_account,
                            can_get_all_accounts,
                            can_get_domain_accounts);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetSignatories &get_signatories) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_signatories.accountId(),
                            *_wsvQuery,
                            can_get_my_signatories,
                            can_get_all_signatories,
                            can_get_domain_signatories);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAccountAssets &get_account_assets) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_account_assets.accountId(),
                            *_wsvQuery,
                            can_get_my_acc_ast,
                            can_get_all_acc_ast,
                            can_get_domain_acc_ast);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAccountDetail &get_account_detail) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_account_detail.accountId(),
                            *_wsvQuery,
                            can_get_my_acc_detail,
                            can_get_all_acc_detail,
                            can_get_domain_acc_detail);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAccountTransactions
        &get_account_transactions) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_account_transactions.accountId(),
                            *_wsvQuery,
                            can_get_my_acc_txs,
                            can_get_all_acc_txs,
                            can_get_domain_acc_txs);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetAccountAssetTransactions
        &get_account_asset_transactions) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return hasQueryPermission(query.creatorAccountId(),
                            get_account_asset_transactions.accountId(),
                            *_wsvQuery,
                            can_get_my_acc_ast_txs,
                            can_get_all_acc_ast_txs,
                            can_get_domain_acc_ast_txs);
}

bool QueryProcessingFactory::validate(
    const shared_model::interface::Query &query,
    const shared_model::interface::GetTransactions &get_transactions) {
  // TODO: 03.02.2018 grimadas IR-851: check signatures
  return checkAccountRolePermission(
             query.creatorAccountId(), *_wsvQuery, can_get_my_txs)
      or checkAccountRolePermission(
             query.creatorAccountId(), *_wsvQuery, can_get_all_txs);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetAssetInfo(
    const shared_model::interface::GetAssetInfo &query,
    const shared_model::interface::types::HashType &hash) {
  auto ast = _wsvQuery->getAsset(query.assetId());

  if (not ast) {
    return build_error<shared_model::interface::NoAssetErrorResponse>(hash);
  }

  const auto &asset = **ast;
  auto response =
      QueryResponseBuilder()
          .assetResponse(asset.assetId(), asset.domainId(), asset.precision())
          .queryHash(hash)
          .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetRoles(
    const shared_model::interface::GetRoles &query,
    const shared_model::interface::types::HashType &hash) {
  auto roles = _wsvQuery->getRoles();
  if (not roles) {
    return build_error<shared_model::interface::NoRolesErrorResponse>(hash);
  }
  auto response =
      QueryResponseBuilder().rolesResponse(*roles).queryHash(hash).build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetRolePermissions(
    const shared_model::interface::GetRolePermissions &query,
    const shared_model::interface::types::HashType &hash) {
  auto perm = _wsvQuery->getRolePermissions(query.roleId());
  if (not perm) {
    return build_error<shared_model::interface::NoRolesErrorResponse>(hash);
  }

  auto response = QueryResponseBuilder()
                      .rolePermissionsResponse(*perm)
                      .queryHash(hash)
                      .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetAccount(
    const shared_model::interface::GetAccount &query,
    const shared_model::interface::types::HashType &hash) {
  auto acc = _wsvQuery->getAccount(query.accountId());

  auto roles = _wsvQuery->getAccountRoles(query.accountId());
  if (not acc or not roles) {
    return build_error<shared_model::interface::NoAccountErrorResponse>(hash);
  }

  auto account = std::static_pointer_cast<shared_model::proto::Account>(*acc);
  auto response = QueryResponseBuilder()
                      .accountResponse(*account, *roles)
                      .queryHash(hash)
                      .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetAccountAssets(
    const shared_model::interface::GetAccountAssets &query,
    const shared_model::interface::types::HashType &hash) {
  auto acct_asset =
      _wsvQuery->getAccountAsset(query.accountId(), query.assetId());

  if (not acct_asset) {
    return build_error<shared_model::interface::NoAccountAssetsErrorResponse>(
        hash);
  }

  const auto &account_asset = **acct_asset;
  auto response = QueryResponseBuilder()
                      .accountAssetResponse(account_asset.assetId(),
                                            account_asset.accountId(),
                                            account_asset.balance())
                      .queryHash(hash)
                      .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
iroha::model::QueryProcessingFactory::executeGetAccountDetail(
    const shared_model::interface::GetAccountDetail &query,
    const shared_model::interface::types::HashType &hash) {
  auto acct_detail = _wsvQuery->getAccountDetail(query.accountId());
  if (not acct_detail) {
    return build_error<shared_model::interface::NoAccountDetailErrorResponse>(
        hash);
  }
  auto response = QueryResponseBuilder()
                      .accountDetailResponse(*acct_detail)
                      .queryHash(hash)
                      .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
iroha::model::QueryProcessingFactory::executeGetAccountAssetTransactions(
    const shared_model::interface::GetAccountAssetTransactions &query,
    const shared_model::interface::types::HashType &hash) {
  auto acc_asset_tx = _blockQuery->getAccountAssetTransactions(
      query.accountId(), query.assetId());

  auto tmp =
      acc_asset_tx
          .reduce(std::vector<
                      std::shared_ptr<shared_model::interface::Transaction>>{},
                  [](auto &&vec, const auto &tx) {
                    vec.push_back(tx);
                    return vec;
                  },
                  [](auto &&response) { return response; })
          .as_blocking()
          .first();

  std::vector<shared_model::proto::Transaction> txs;
  for (const auto &tx : tmp) {
    txs.push_back(
        *std::static_pointer_cast<shared_model::proto::Transaction>(tx));
  }

  auto response =
      QueryResponseBuilder().transactionsResponse(txs).queryHash(hash).build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetAccountTransactions(
    const shared_model::interface::GetAccountTransactions &query,
    const shared_model::interface::types::HashType &hash) {
  auto acc_tx = _blockQuery->getAccountTransactions(query.accountId());

  auto tmp =
      acc_tx
          .reduce(std::vector<
                      std::shared_ptr<shared_model::interface::Transaction>>{},
                  [](auto &&vec, const auto &tx) {
                    vec.push_back(tx);
                    return vec;
                  },
                  [](auto &&response) { return response; })
          .as_blocking()
          .first();

  std::vector<shared_model::proto::Transaction> txs;
  for (const auto &tx : tmp) {
    txs.push_back(
        *std::static_pointer_cast<shared_model::proto::Transaction>(tx));
  }

  auto response =
      QueryResponseBuilder().transactionsResponse(txs).queryHash(hash).build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
iroha::model::QueryProcessingFactory::executeGetTransactions(
    const shared_model::interface::GetTransactions &query,
    const shared_model::interface::types::HashType &hash) {
  const std::vector<shared_model::crypto::Hash> &hashes =
      query.transactionHashes();

  auto transactions = _blockQuery->getTransactions(hashes);

  auto tmp =
      transactions
          .reduce(std::vector<
                      std::shared_ptr<shared_model::interface::Transaction>>{},
                  [](auto &&vec, const auto &tx) {
                    if (tx) {
                      vec.push_back(*tx);
                    }
                    return vec;
                  },
                  [](auto &&response) { return response; })
          .as_blocking()
          .first();

  std::vector<shared_model::proto::Transaction> txs;
  for (const auto &tx : tmp) {
    txs.push_back(
        *std::static_pointer_cast<shared_model::proto::Transaction>(tx));
  }
  auto response =
      QueryResponseBuilder().transactionsResponse(txs).queryHash(hash).build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::executeGetSignatories(
    const shared_model::interface::GetSignatories &query,
    const shared_model::interface::types::HashType &hash) {
  auto signs = _wsvQuery->getSignatories(query.accountId());
  if (not signs) {
    return build_error<shared_model::interface::NoSignatoriesErrorResponse>(
        hash);
  }
  auto response = QueryResponseBuilder()
                      .signatoriesResponse(*signs)
                      .queryHash(hash)
                      .build();
  return clone(response);
}

std::shared_ptr<shared_model::interface::QueryResponse>
QueryProcessingFactory::execute(const shared_model::interface::Query &query) {
  const auto &query_hash = query.hash();
  return visit_in_place(
      query.get(),
      [&](const w<shared_model::interface::GetAccount> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAccount(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetSignatories> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetSignatories(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetAccountTransactions> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAccountTransactions(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetTransactions> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetTransactions(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetAccountAssetTransactions> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAccountAssetTransactions(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetAccountAssets> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAccountAssets(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetAccountDetail> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAccountDetail(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetRoles> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetRoles(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetRolePermissions> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetRolePermissions(*q, query_hash);
      },
      [&](const w<shared_model::interface::GetAssetInfo> &q) {
        if (not validate(query, *q)) {
          return build_error<
              shared_model::interface::StatefulFailedErrorResponse>(query_hash);
        }
        return executeGetAssetInfo(*q, query_hash);
      }

  );
}
