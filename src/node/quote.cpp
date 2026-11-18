// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/crypto/cose.h"
#include "ccf/ds/json.h"
#include "ccf/historical_queries_utils.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/attestation_tdx.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/node_join_policy.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/tcb_verification.h"
#include "ccf/service/tables/tdx_config_id.h"
#include "ccf/service/tables/tdx_measurements.h"
#include "ccf/service/tables/tdx_tcb_policy.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "ccf/service/tables/virtual_measurements.h"
#include "crypto/cose_utils.h"
#include "ds/internal_logger.h"
#include "node/js_policy.h"
#include "node/uvm_endorsements.h"

#include <algorithm>

namespace ccf
{
  bool verify_enclave_measurement_against_uvm_endorsements(
    ccf::kv::ReadOnlyTx& tx,
    const pal::PlatformAttestationMeasurement& quote_measurement,
    const std::vector<uint8_t>& uvm_endorsements)
  {
    // Uses KV-defined roots of trust (did -> (feed, svn)) to verify the
    // UVM measurement against endorsements in the quote.
    std::vector<pal::UVMEndorsements> uvm_roots_of_trust_from_kv;
    auto* uvmes = tx.ro<SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
    if (uvmes != nullptr)
    {
      uvmes->foreach(
        [&uvm_roots_of_trust_from_kv](
          const DID& did, const FeedToEndorsementsDataMap& endorsements_map) {
          for (const auto& [feed, data] : endorsements_map)
          {
            uvm_roots_of_trust_from_kv.push_back(
              pal::UVMEndorsements{did, feed, data.svn});
          }
          return true;
        });
    }

    try
    {
      auto uvm_endorsements_data =
        verify_uvm_endorsements_against_roots_of_trust(
          uvm_endorsements, quote_measurement, uvm_roots_of_trust_from_kv);
      return true;
    }
    catch (const std::logic_error& e)
    {
      LOG_FAIL_FMT("Failed to verify UVM endorsements: {}", e.what());
      return false;
    }
  }

  QuoteVerificationResult verify_enclave_measurement_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const pal::PlatformAttestationMeasurement& quote_measurement,
    const QuoteFormat& quote_format,
    const std::optional<std::vector<uint8_t>>& uvm_endorsements = std::nullopt)
  {
    switch (quote_format)
    {
      case QuoteFormat::oe_sgx_v1:
      {
        if (!tx.ro<CodeIDs>(Tables::NODE_CODE_IDS)
               ->has(pal::SgxAttestationMeasurement(quote_measurement)))
        {
          return QuoteVerificationResult::FailedMeasurementNotFound;
        }
        break;
      }
      case QuoteFormat::insecure_virtual:
      {
        if (!tx.ro<VirtualMeasurements>(Tables::NODE_VIRTUAL_MEASUREMENTS)
               ->has(pal::VirtualAttestationMeasurement(
                 quote_measurement.data.begin(), quote_measurement.data.end())))
        {
          return QuoteVerificationResult::FailedMeasurementNotFound;
        }
        break;
      }
      case QuoteFormat::intel_tdx_v1:
      {
        if (!tx.ro<TdxMeasurements>(Tables::NODE_TDX_MEASUREMENTS)
               ->has(pal::TdxAttestationMeasurement(quote_measurement)))
        {
          return QuoteVerificationResult::FailedMeasurementNotFound;
        }
        break;
      }
      case QuoteFormat::amd_sev_snp_v1:
      {
        // Check for UVM endorsements first as they provide better
        // serviceability.
        if (uvm_endorsements.has_value())
        {
          if (!verify_enclave_measurement_against_uvm_endorsements(
                tx, quote_measurement, uvm_endorsements.value()))
          {
            return QuoteVerificationResult::FailedUVMEndorsementsNotFound;
          }
        }
        else
        {
          if (!tx.ro<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)
                 ->has(pal::SnpAttestationMeasurement(quote_measurement)))
          {
            return QuoteVerificationResult::FailedMeasurementNotFound;
          }
        }
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unexpected quote format {} when verifying quote against store",
          quote_format));
      }
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult verify_quoted_node_public_key(
    const std::vector<uint8_t>& expected_node_public_key,
    const ccf::crypto::Sha256Hash& quoted_hash)
  {
    if (quoted_hash != ccf::crypto::Sha256Hash(expected_node_public_key))
    {
      return QuoteVerificationResult::FailedInvalidQuotedPublicKey;
    }

    return QuoteVerificationResult::Verified;
  }

  std::optional<pal::PlatformAttestationMeasurement> AttestationProvider::
    get_measurement(const QuoteInfo& quote_info)
  {
    pal::PlatformAttestationMeasurement measurement = {};
    pal::PlatformAttestationReportData r = {};
    try
    {
      pal::verify_quote(quote_info, measurement, r);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return std::nullopt;
    }

    return measurement;
  }

  std::optional<pal::snp::Attestation> AttestationProvider::get_snp_attestation(
    const QuoteInfo& quote_info)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      return std::nullopt;
    }
    try
    {
      pal::PlatformAttestationMeasurement d = {};
      pal::PlatformAttestationReportData r = {};
      pal::verify_quote(quote_info, d, r);
      auto attestation = *reinterpret_cast<const pal::snp::Attestation*>(
        quote_info.quote.data());
      return attestation;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify local attestation report: {}", e.what());
      return std::nullopt;
    }
  }

  // The platform-neutral configuration identity: what the workload was launched
  // *with*, as opposed to the launch measurement, which is what was launched.
  //
  // Returned as a variable-length value because the platforms disagree on width
  // -- SEV-SNP HOST_DATA is 32 bytes, TDX MRCONFIGID is 48 -- and truncating
  // one to fit the other would mean the value CCF records is not the value the
  // hardware attested.
  std::optional<pal::PlatformAttestationMeasurement> AttestationProvider::
    get_config_id(const QuoteInfo& quote_info)
  {
    switch (quote_info.format)
    {
      case QuoteFormat::insecure_virtual:
      {
        auto j = ccf::parse_json_safe(quote_info.quote);

        auto it = j.find("host_data");
        if (it == j.end())
        {
          LOG_FAIL_FMT(
            "No security policy in virtual attestation from which to derive "
            "host data");
          return std::nullopt;
        }

        pal::PlatformAttestationMeasurement config_id{};
        config_id.data = ccf::ds::from_hex(it->get<std::string>());
        return config_id;
      }

      case QuoteFormat::amd_sev_snp_v1:
      {
        pal::PlatformAttestationMeasurement d = {};
        pal::PlatformAttestationReportData r = {};
        try
        {
          pal::verify_quote(quote_info, d, r);
          auto quote = *reinterpret_cast<const pal::snp::Attestation*>(
            quote_info.quote.data());
          pal::PlatformAttestationMeasurement config_id{};
          config_id.data.assign(
            std::begin(quote.host_data), std::end(quote.host_data));
          return config_id;
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
          return std::nullopt;
        }
      }

      case QuoteFormat::intel_tdx_v1:
      {
        try
        {
          return pal::tdx::verify(quote_info).config_id;
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
          return std::nullopt;
        }
      }

      case QuoteFormat::oe_sgx_v1:
      {
        // SGX has no settable launch configuration claim.
        return std::nullopt;
      }
    }

    return std::nullopt;
  }

  // The 32-bit-wide view of the configuration identity, for the platforms whose
  // claim really is a SHA-256: SEV-SNP HOST_DATA and the virtual equivalent.
  // Intel TDX has no representation here -- MRCONFIGID does not fit -- so
  // callers that must work across platforms should use get_config_id().
  std::optional<HostData> AttestationProvider::get_host_data(
    const QuoteInfo& quote_info)
  {
    if (
      quote_info.format != QuoteFormat::amd_sev_snp_v1 &&
      quote_info.format != QuoteFormat::insecure_virtual)
    {
      return std::nullopt;
    }

    auto config_id = get_config_id(quote_info);
    if (!config_id.has_value())
    {
      return std::nullopt;
    }

    if (config_id->data.size() != HostData::SIZE)
    {
      LOG_FAIL_FMT(
        "Configuration identity is {} bytes, which does not fit HostData ({})",
        config_id->data.size(),
        HostData::SIZE);
      return std::nullopt;
    }

    HostData::Representation rep{};
    std::copy(config_id->data.begin(), config_id->data.end(), rep.begin());
    return HostData::from_representation(rep);
  }

  // Check the configuration identity a node was launched with against the set
  // the consortium has approved. Each platform has its own table, because each
  // platform's claim is a different width and means a different thing.
  QuoteVerificationResult verify_config_id_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    std::optional<pal::PlatformAttestationMeasurement>& config_id)
  {
    if (
      quote_info.format != QuoteFormat::amd_sev_snp_v1 &&
      quote_info.format != QuoteFormat::insecure_virtual &&
      quote_info.format != QuoteFormat::intel_tdx_v1)
    {
      throw std::logic_error(
        "Attempted to verify configuration identity for an unsupported "
        "platform");
    }

    config_id = AttestationProvider::get_config_id(quote_info);
    if (!config_id.has_value())
    {
      return QuoteVerificationResult::FailedHostDataDigestNotFound;
    }

    bool accepted_policy = false;

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      auto* accepted_policies_table =
        tx.ro<VirtualHostDataMap>(Tables::VIRTUAL_HOST_DATA);
      accepted_policy =
        accepted_policies_table->contains(HostData(config_id->data));
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      auto* accepted_policies_table = tx.ro<SnpHostDataMap>(Tables::HOST_DATA);
      accepted_policy = accepted_policies_table->has(HostData(config_id->data));
    }
    else if (quote_info.format == QuoteFormat::intel_tdx_v1)
    {
      auto* accepted_policies_table =
        tx.ro<TdxConfigIdMap>(Tables::NODE_TDX_CONFIG_ID);
      accepted_policy =
        accepted_policies_table->has(pal::TdxConfigId(config_id->data));
    }

    if (!accepted_policy)
    {
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  // Whether a joining TDX node's platform is current enough for the consortium.
  //
  // Distinct from the appraisal libcnap already performed, which answers "is
  // this platform current according to Intel, under the policy *this node* was
  // configured with". This answers "is that good enough for this service",
  // using a floor the consortium set, so a node cannot admit itself by
  // configuring a lax local policy or by presenting older collateral under
  // which it still looks current.
  QuoteVerificationResult verify_tdx_tcb_against_store(
    ccf::kv::ReadOnlyTx& tx, const QuoteInfo& quote_info)
  {
    pal::tdx::Verdict verdict;
    try
    {
      verdict = pal::tdx::verify(quote_info);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return QuoteVerificationResult::Failed;
    }

    auto* policies = tx.ro<TdxTcbPolicyMap>(Tables::TDX_TCB_POLICIES);

    // An entry for this platform model, else the default entry under the empty
    // key. If the consortium has set neither, there is no floor to meet.
    auto policy = policies->get(verdict.fmspc);
    if (!policy.has_value())
    {
      policy = policies->get("");
    }
    if (!policy.has_value())
    {
      LOG_INFO_FMT(
        "Intel TDX: no TCB policy set for FMSPC {} and no default, so no "
        "consortium floor is applied to this node",
        verdict.fmspc);
      return QuoteVerificationResult::Verified;
    }

    if (
      verdict.tcb_evaluation_data_number <
      policy->minimum_tcb_evaluation_data_number)
    {
      LOG_FAIL_FMT(
        "Intel TDX: node was appraised against TCB evaluation data number {}, "
        "below the required minimum {}",
        verdict.tcb_evaluation_data_number,
        policy->minimum_tcb_evaluation_data_number);
      return QuoteVerificationResult::FailedInvalidTcbVersion;
    }

    if (
      !policy->tcb_channel.empty() &&
      verdict.tcb_channel != policy->tcb_channel)
    {
      LOG_FAIL_FMT(
        "Intel TDX: node was appraised against the {} collateral channel, but "
        "this service requires {}",
        verdict.tcb_channel,
        policy->tcb_channel);
      return QuoteVerificationResult::FailedInvalidTcbVersion;
    }

    // Empty means UpToDate only, rather than "anything goes".
    const auto& accepted = policy->accepted_tcb_statuses;
    const bool status_ok = accepted.empty() ?
      verdict.tcb_status == "UpToDate" :
      std::find(accepted.begin(), accepted.end(), verdict.tcb_status) !=
        accepted.end();
    if (!status_ok)
    {
      LOG_FAIL_FMT(
        "Intel TDX: node presented TCB status {}, which this service does not "
        "accept",
        verdict.tcb_status);
      return QuoteVerificationResult::FailedInvalidTcbVersion;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult verify_tcb_version_against_store(
    ccf::kv::ReadOnlyTx& tx, const QuoteInfo& quote_info)
  {
    if (quote_info.format == QuoteFormat::intel_tdx_v1)
    {
      return verify_tdx_tcb_against_store(tx, quote_info);
    }

    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      return QuoteVerificationResult::Verified;
    }

    pal::PlatformAttestationMeasurement d = {};
    pal::PlatformAttestationReportData r = {};
    pal::verify_quote(quote_info, d, r);
    auto attestation =
      *reinterpret_cast<const pal::snp::Attestation*>(quote_info.quote.data());

    std::optional<pal::snp::TcbVersionPolicy> min_tcb_opt = std::nullopt;
    auto* h = tx.ro<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS);
    h->foreach(
      [&min_tcb_opt, &attestation](
        const std::string& cpuid_hex, const pal::snp::TcbVersionPolicy& v) {
        auto cpuid = pal::snp::cpuid_from_hex(cpuid_hex);
        if (
          cpuid.get_family_id() == attestation.cpuid_fam_id &&
          cpuid.get_model_id() == attestation.cpuid_mod_id &&
          cpuid.stepping == attestation.cpuid_step)
        {
          min_tcb_opt = v;
          return false;
        }
        return true;
      });

    if (!min_tcb_opt.has_value())
    {
      return QuoteVerificationResult::FailedInvalidCPUID;
    }
    // CPUID of the attested cpu must now be equal to the min_tcb_opt's cpuid

    auto product_family = pal::snp::get_sev_snp_product(
      attestation.cpuid_fam_id, attestation.cpuid_mod_id);
    auto attestation_tcb_policy =
      attestation.reported_tcb.to_policy(product_family);

    if (pal::snp::TcbVersionPolicy::is_valid(
          min_tcb_opt.value(), attestation_tcb_policy))
    {
      return QuoteVerificationResult::Verified;
    }
    return QuoteVerificationResult::FailedInvalidTcbVersion;
  }

  namespace
  {
    ccf::crypto::Pem resolve_pubkey_from_x5chain_and_issuer(
      const std::vector<std::vector<uint8_t>>& x5chain,
      const std::string& issuer_did)
    {
      std::vector<std::string> pem_chain;
      pem_chain.reserve(x5chain.size());
      for (const auto& c : x5chain)
      {
        pem_chain.emplace_back(ccf::crypto::cert_der_to_pem(c).str());
      }

      auto jwk =
        ccf::parse_json_safe(didx509::resolve_jwk(pem_chain, issuer_did, true));
      auto generic_jwk = jwk.get<ccf::crypto::JsonWebKey>();

      if (generic_jwk.kty != ccf::crypto::JsonWebKeyType::EC)
      {
        throw std::logic_error(fmt::format(
          "Unsupported key type ({}) for DID {}", generic_jwk.kty, issuer_did));
      }

      auto ec_jwk = jwk.get<ccf::crypto::JsonWebKeyECPublic>();
      return ccf::crypto::make_ec_public_key(ec_jwk)->public_key_pem();
    }

    // Verify the COSE_Sign1 signature and that the payload matches the
    // expected host_data.  Returns the decoded protected header on success.
    cose::Sign1ProtectedHeader verify_ts_signature_and_payload(
      const ccf::cbor::Value& cose_array,
      const pal::PlatformAttestationMeasurement& config_id)
    {
      const auto& phdr_raw = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& { return cose_array->array_at(0); },
        "COSE_Sign1 protected header");
      auto phdr_cbor = ccf::cbor::rethrow_with_msg(
        [&]() { return ccf::cbor::parse(phdr_raw->as_bytes()); },
        "Parse protected header");

      auto h = cose::decode_sign1_protected_header(phdr_cbor);

      if (h.x5chain.empty())
      {
        throw std::logic_error(
          "No certificates in transparent statement x5chain");
      }
      if (h.cwt.iss.empty())
      {
        throw std::logic_error("No CWT issuer in transparent statement");
      }

      cose::validate_cwt_iat_against_x5chain(
        h.cwt, h.x5chain, "code transparent statement");

      auto pubk = resolve_pubkey_from_x5chain_and_issuer(h.x5chain, h.cwt.iss);
      auto verifier = ccf::crypto::make_cose_verifier_from_key(pubk);

      auto payload = ccf::cbor::rethrow_with_msg(
        [&]() { return cose_array->array_at(2)->as_bytes(); },
        "COSE_Sign1 payload");
      auto sig_bytes = ccf::cbor::rethrow_with_msg(
        [&]() { return cose_array->array_at(3)->as_bytes(); },
        "COSE_Sign1 signature");

      if (!verifier->verify_decomposed(
            phdr_raw->as_bytes(), payload, sig_bytes, h.alg))
      {
        throw std::logic_error(
          "Transparent statement signature verification failed");
      }

      // Compared at the platform's own width rather than a fixed 32 bytes, so
      // the same mechanism endorses a 32-byte SEV-SNP HOST_DATA and a 48-byte
      // TDX MRCONFIGID without either being padded or truncated to fit.
      if (
        payload.size() != config_id.data.size() ||
        std::memcmp(
          payload.data(), config_id.data.data(), config_id.data.size()) != 0)
      {
        throw std::logic_error(fmt::format(
          "Transparent statement payload ({}) does not match the attested "
          "configuration identity ({})",
          ccf::ds::to_hex(payload),
          config_id.hex_str()));
      }

      return h;
    }

    // Parse and verify all receipts attached to the transparent statement.
    // Returns the collected policy inputs for each receipt.
    std::vector<ccf::policy::ReceiptPolicyInput> verify_ts_receipts(
      const std::vector<uint8_t>& ts_raw,
      const ccf::cbor::Value& cose_array,
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem)
    {
      const auto& uhdr = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& { return cose_array->array_at(1); },
        "Parse transparent statement unprotected header");

      const auto& receipts_array = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& {
          return uhdr->map_at(
            ccf::cbor::make_signed(ccf::cose::header::iana::VDP));
        },
        "Parse receipts array from unprotected header");

      const auto num_receipts = receipts_array->size();
      if (num_receipts == 0)
      {
        throw std::logic_error("No receipts in transparent statement");
      }

      if (!network_identity_subsystem)
      {
        throw std::logic_error(
          "Network identity subsystem not available for receipt "
          "verification");
      }

      auto signed_statement = ccf::cose::edit::set_unprotected_header(
        ts_raw, ccf::cose::edit::desc::Empty{});
      auto expected_claims_digest = ccf::crypto::Sha256Hash(signed_statement);

      std::vector<ccf::policy::ReceiptPolicyInput> inputs;

      for (size_t i = 0; i < num_receipts; ++i)
      {
        const auto& receipt_bytes = ccf::cbor::rethrow_with_msg(
          [&]() { return receipts_array->array_at(i)->as_bytes(); },
          fmt::format("Extract receipt {} from array", i));

        std::vector<uint8_t> receipt_raw(
          receipt_bytes.begin(), receipt_bytes.end());

        auto receipt_cbor = ccf::cbor::rethrow_with_msg(
          [&]() { return ccf::cbor::parse(receipt_raw); },
          fmt::format("Parse receipt {} COSE envelope", i));

        const auto& receipt_envelope = ccf::cbor::rethrow_with_msg(
          [&]() -> const ccf::cbor::Value& {
            return receipt_cbor->tag_at(ccf::cbor::tag::COSE_SIGN_1);
          },
          fmt::format("Parse receipt {} COSE_Sign1 tag", i));

        auto receipt_phdr_raw = ccf::cbor::rethrow_with_msg(
          [&]() -> const ccf::cbor::Value& {
            return receipt_envelope->array_at(0);
          },
          fmt::format("Parse receipt {} protected header bytes", i));
        auto receipt_phdr_cbor = ccf::cbor::rethrow_with_msg(
          [&]() { return ccf::cbor::parse(receipt_phdr_raw->as_bytes()); },
          fmt::format("Decode receipt {} protected header", i));
        auto decoded_receipt_phdr =
          cose::decode_ccf_receipt_phdr(receipt_phdr_cbor);

        auto proofs = cose::decode_merkle_proofs(receipt_envelope);
        if (proofs.empty())
        {
          throw std::logic_error(
            fmt::format("No Merkle proofs found in receipt {}", i));
        }

        for (const auto& proof : proofs)
        {
          if (
            proof.leaf.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE ||
            std::memcmp(
              proof.leaf.claims_digest.data(),
              expected_claims_digest.h.data(),
              ccf::crypto::Sha256Hash::SIZE) != 0)
          {
            throw std::logic_error(fmt::format(
              "Receipt {} claims_digest ({}) does not match signed "
              "statement hash ({})",
              i,
              ccf::ds::to_hex(proof.leaf.claims_digest),
              expected_claims_digest.hex_str()));
          }
        }

        std::vector<cose::Leaf> receipt_leaves;
        receipt_leaves.reserve(proofs.size());
        for (const auto& proof : proofs)
        {
          receipt_leaves.push_back(proof.leaf);
        }
        inputs.push_back(
          {std::move(decoded_receipt_phdr), std::move(receipt_leaves)});

        ccf::historical::verify_self_issued_receipt(
          receipt_raw, network_identity_subsystem);
      }

      return inputs;
    }

    // Look up the code update policy from the KV store and evaluate it
    // against the transparent statement inputs.
    void apply_code_update_policy(
      ccf::kv::ReadOnlyTx& tx,
      const cose::Sign1ProtectedHeader& phdr,
      std::vector<ccf::policy::ReceiptPolicyInput> receipt_inputs)
    {
      auto* policy_table = tx.ro<CodeUpdatePolicy>(Tables::NODE_JOIN_POLICY);
      if (policy_table == nullptr)
      {
        throw std::logic_error("No code update policy table available");
      }

      auto policy_script = policy_table->get();
      if (!policy_script.has_value())
      {
        throw std::logic_error("No code update policy set");
      }

      std::vector<ccf::policy::TransparentStatementPolicyInput> inputs;
      inputs.push_back({phdr, std::move(receipt_inputs)});

      std::optional<std::string> violation;
      try
      {
        violation =
          ccf::policy::apply_node_join_policy(policy_script.value(), inputs);
      }
      catch (const std::runtime_error& e)
      {
        throw std::logic_error(
          fmt::format("Failed to populate JS policy inputs: {}", e.what()));
      }
      if (violation.has_value())
      {
        throw std::logic_error(fmt::format(
          "Code update policy rejected transparent statement: {}",
          violation.value()));
      }
    }
  }

  QuoteVerificationResult verify_code_transparent_statement(
    ccf::kv::ReadOnlyTx& tx,
    const std::vector<uint8_t>& ts_raw,
    const pal::PlatformAttestationMeasurement& config_id,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem)
  {
    try
    {
      auto parsed = ccf::cbor::rethrow_with_msg(
        [&]() { return ccf::cbor::parse(ts_raw); },
        "Transparent statement COSE envelope");

      const auto& cose_array = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& {
          return parsed->tag_at(ccf::cbor::tag::COSE_SIGN_1);
        },
        "COSE_Sign1 tag");

      auto phdr = verify_ts_signature_and_payload(cose_array, config_id);

      auto receipt_inputs =
        verify_ts_receipts(ts_raw, cose_array, network_identity_subsystem);

      apply_code_update_policy(tx, phdr, std::move(receipt_inputs));
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify code transparent statement: {}", e.what());
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult AttestationProvider::verify_quote_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    const std::vector<uint8_t>& expected_node_public_key_der,
    pal::PlatformAttestationMeasurement& measurement,
    const std::optional<std::vector<uint8_t>>& code_transparent_statement,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem)
  {
    ccf::crypto::Sha256Hash quoted_hash;
    pal::PlatformAttestationReportData report_data;
    try
    {
      pal::verify_quote(quote_info, measurement, report_data);
      quoted_hash = report_data.to_sha256_hash();
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return QuoteVerificationResult::Failed;
    }

    std::optional<pal::PlatformAttestationMeasurement> config_id{std::nullopt};
    auto rc = verify_config_id_against_store(tx, quote_info, config_id);
    if (rc == QuoteVerificationResult::FailedInvalidHostData)
    {
      if (code_transparent_statement.has_value())
      {
        if (!config_id.has_value())
        {
          // It must not happen after verify_config_id_against_store returns
          // FailedInvalidHostData, but let's handle gracefully.
          return QuoteVerificationResult::FailedHostDataDigestNotFound;
        }

        rc = verify_code_transparent_statement(
          tx,
          code_transparent_statement.value(),
          config_id.value(),
          network_identity_subsystem);
      }
    }

    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    rc = verify_enclave_measurement_against_store(
      tx, measurement, quote_info.format, quote_info.uvm_endorsements);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    rc = verify_tcb_version_against_store(tx, quote_info);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}