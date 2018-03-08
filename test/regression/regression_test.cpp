//
// Created by igor on 07.03.18.
//

#include <gtest/gtest.h>

#include "builders/protobuf/transaction.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"

constexpr auto kUser = "user@test";
constexpr auto kAsset = "asset#domain";
const auto kAdminOldKeypair = iroha::create_keypair();
const shared_model::crypto::Keypair kAdminKeypair(
    shared_model::crypto::PublicKey(kAdminOldKeypair.pubkey.to_string()),
    shared_model::crypto::PrivateKey(kAdminOldKeypair.privkey.to_string()));

/**
 * @given ITF instance with Iroha
 * @when existing ITF instance was not gracefully shutdown
 * @then following ITF instantiation should not cause any errors
 */
TEST(RegressionTest, SequentialInitialization) {
  auto tx = shared_model::proto::TransactionBuilder()
                .createdTime(iroha::time::now())
                .creatorAccountId(kUser)
                .txCounter(1)
                .addAssetQuantity(kUser, kAsset, "1.0")
                .build()
                .signAndAddSignature(
                    shared_model::crypto::DefaultCryptoAlgorithmType::
                        generateKeypair());

  auto checkStatelessValid = [](auto &status) {
    ASSERT_NO_THROW(
        boost::get<shared_model::detail::
                       PolymorphicWrapper<shared_model::interface::
                                              StatelessValidTxResponse>>(
            status.get()));
  };
  auto checkProposal = [](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), 1);
  };
  auto checkBlock = [](auto &block) {
    ASSERT_EQ(block->transactions().size(), 0);
  };
  {
    integration_framework::IntegrationTestFramework(
        10,
        [](integration_framework::IntegrationTestFramework *this_) {
          /* TODO Igor Egorov, 08.03.2018, IR-1085
           * find another way to shutdown ITF without hang */
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        })
        .setInitialState(kAdminKeypair)
        .sendTx(tx, checkStatelessValid)
        .skipProposal()
        .skipBlock();
  }
  {
    integration_framework::IntegrationTestFramework()
        .setInitialState(kAdminKeypair)
        .sendTx(tx, checkStatelessValid)
        .checkProposal(checkProposal)
        .checkBlock(checkBlock)
        .done();
  }
}
