// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/quote_info.h"
#include "ccf/network_identity_interface.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/tx.h"

#include <memory>
#include <optional>
#include <vector>

namespace ccf
{
  enum class QuoteVerificationResult : uint8_t
  {
    Verified = 0,
    Failed,
    FailedMeasurementNotFound,
    FailedHostDataDigestNotFound,
    FailedInvalidHostData,
    FailedInvalidQuotedPublicKey,
    FailedUVMEndorsementsNotFound,
    FailedInvalidCPUID,
    FailedInvalidTcbVersion
  };

  class AttestationProvider
  {
  public:
    /// In SGX case, extracts the MRENCLAVE from an OE quote. This fails on
    /// quotes with expired collateral, so it is recommended to cache code IDs
    /// once they have been successfully extracted.
    static std::optional<pal::PlatformAttestationMeasurement> get_measurement(
      const QuoteInfo& quote_info);

    /// The configuration identity the node was launched with, at the width the
    /// platform actually attests: 32 bytes for SEV-SNP HOST_DATA and the
    /// virtual equivalent, 48 for Intel TDX MRCONFIGID. Prefer this to
    /// get_host_data() in anything that must work across platforms.
    static std::optional<pal::PlatformAttestationMeasurement> get_config_id(
      const QuoteInfo& quote_info);

    /// The SHA-256-shaped view of the above. Returns nullopt on platforms whose
    /// configuration identity does not fit, which includes Intel TDX.
    static std::optional<HostData> get_host_data(const QuoteInfo& quote_info);

    static std::optional<pal::snp::Attestation> get_snp_attestation(
      const QuoteInfo& quote_info);

    static QuoteVerificationResult verify_quote_against_store(
      ccf::kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement,
      const std::optional<std::vector<uint8_t>>& code_transparent_statement,
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem = nullptr);
  };
  QuoteVerificationResult verify_tcb_version_against_store(
    ccf::kv::ReadOnlyTx& tx, const QuoteInfo& quote_info);

}