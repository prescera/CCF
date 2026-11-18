// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation.h"

#include <optional>
#include <string>

namespace ccf::pal::tdx
{
  // Where this node's endorsing collateral comes from, and under what policy it
  // is appraised.
  //
  // Unlike SEV-SNP, a TDX quote does not travel with its endorsements. Intel's
  // collateral is published per platform *model* (identified by FMSPC), not per
  // node, and it expires roughly monthly, so it is supplied to the platform
  // out-of-band -- across a data diode in an air-gapped deployment -- as a
  // signed bundle on disk. Each node therefore appraises every quote it sees,
  // its own and its peers', against its own locally supplied bundle. A node
  // joining from a platform model this node has no collateral for will fail
  // verification with an absent-platform error, which is the correct and
  // legible outcome.
  struct CollateralConfig
  {
    // A bundle directory, or a root containing a `current` symlink to one. The
    // library verifies the bundle's Ed25519 signature before parsing anything
    // in it, so this path does not need to be on trusted storage.
    std::string bundle_dir;

    // 64 hex characters: the Ed25519 public key the bundle manifest is signed
    // with. This is the trust anchor for the collateral supply chain and
    // belongs in the node's configuration, not in the bundle.
    std::string syncer_pubkey_hex;

    // A libcnap HardwarePolicy as JSON: accepted TCB statuses, the TCB channel
    // (`standard` or `early`), advisory denylist, freshness grace windows.
    // Absent means the library's default policy, which accepts UpToDate and
    // SwHardeningNeeded on the `standard` channel with no grace anywhere.
    //
    // Note that the channel is a deployment decision that can flip a verdict on
    // otherwise identical hardware: the same quote can be UpToDate against
    // `standard` and OutOfDate against `early`. It has no safe default and
    // should be set deliberately.
    std::optional<std::string> policy_json = std::nullopt;

    bool operator==(const CollateralConfig&) const = default;
  };

  // Install the collateral configuration for this process. Must be called
  // before any quote is generated or verified, and is a no-op on platforms
  // other than TDX. Mirrors how `ccf::pal::platform` is settled once during
  // startup: quote verification is reached through `verify_quote()`, whose
  // signature carries no configuration, so the configuration is process state
  // rather than a parameter.
  void set_collateral_config(const CollateralConfig& config);

  // Whether a collateral configuration has been installed. Verification of a
  // TDX quote without one is an error, not an unverified pass.
  bool has_collateral_config();

  // What libcnap concluded about a quote, in CCF's vocabulary.
  //
  // A verdict is the audit trail behind a trust decision, so more than the two
  // values `verify_quote()` can return is carried here: the TCB appraisal and
  // the collateral that produced it are what a join policy needs to judge, and
  // what an auditor re-reading the ledger later needs to see.
  struct Verdict
  {
    // MRTD: the launch measurement, 48 bytes.
    PlatformAttestationMeasurement launch_measurement;
    // MRCONFIGID: the settable launch configuration claim, 48 bytes. On Kata
    // Confidential Containers this is SHA-384 of the TD's initdata document.
    // The SEV-SNP analogue is HOST_DATA, which is 32 bytes -- hence a separate
    // type and a separate KV table rather than a widened HostData.
    PlatformAttestationMeasurement config_id;
    // 64 bytes. CCF places SHA-256 of the node's public key in the first 32.
    std::vector<uint8_t> report_data;
    // RTMR0..RTMR3, 48 bytes each, in register order. On direct boot MRTD
    // measures only the virtual firmware; the guest kernel and command line
    // (and through it a dm-verity root hash) land in RTMR1 and RTMR2, so these
    // are what bind a quote to a guest image. Passed through, not judged.
    std::vector<std::vector<uint8_t>> runtime_measurements;

    // Intel's appraisal of the platform's firmware and microcode state.
    std::string tcb_status;
    // Intel's TCB-recovery counter for the collateral used. Monotonic, and the
    // sane thing for a join policy to set a floor on: it says "collateral at
    // least this recent", which a status string cannot.
    uint32_t tcb_evaluation_data_number = 0;
    // "standard" or "early". The same quote can be UpToDate on one and
    // OutOfDate on the other, so a verdict is meaningless without it.
    std::string tcb_channel;
    // The platform model and configuration this quote came from, 12 hex
    // characters. Intel publishes collateral per FMSPC, so this is also the
    // granularity at which a join policy is expressed.
    std::string fmspc;
    std::vector<std::string> advisory_ids;

    // Non-empty if a configured grace window let evidence pass that would
    // otherwise have been rejected. Never silent.
    bool degraded = false;
  };

  // Verify a TDX quote and return everything CCF needs from it.
  //
  // Throws if the quote is not authentic, or if its TCB does not satisfy the
  // locally configured hardware policy. A returned Verdict therefore always
  // describes genuine Intel hardware; whether the measurements it reports are
  // the *approved* ones is a separate, KV-governed question.
  Verdict verify(const QuoteInfo& quote_info);

  // Produce this node's quote over `report_data`, and hand it to the callback.
  //
  // The callback exists for symmetry with the SEV-SNP path, where it is the
  // hook that fetches endorsements from a server before the node may start. On
  // TDX there is nothing to fetch -- collateral is local -- so it is invoked
  // immediately with empty endorsements.
  void generate_tdx_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb);
}
