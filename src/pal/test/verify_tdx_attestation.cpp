// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Verify an Intel TDX quote through CCF's PAL, against a signed collateral
// bundle. The SEV-SNP analogue is verify_attestation.cpp, which fetches its
// endorsements over the network; TDX collateral is supplied locally, so this
// tool takes a bundle directory instead and needs no network at all.
//
// This exercises the whole verification half of the TDX path -- the libcnap
// link, the collateral configuration, the verdict parsing and the claim
// extraction -- on a machine that is not itself a Trust Domain, which is where
// quote *generation* would be needed.

#include "ccf/ds/hex.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_tdx.h"
#include "ccf/pal/measurement.h"
#include "ds/files.h"

#include <CLI11/CLI11.hpp>
#include <iostream>

int main(int argc, char** argv)
{
  CLI::App app{"Intel TDX Attestation Verifier"};

  std::string quote_file;
  app.add_option("--quote", quote_file, "File containing the raw quote")
    ->required();

  std::string bundle_dir;
  app
    .add_option(
      "--bundle",
      bundle_dir,
      "Collateral bundle directory, or a root containing a `current` symlink")
    ->required();

  std::string syncer_pubkey;
  app
    .add_option(
      "--key", syncer_pubkey, "Bundle syncer public key, 32 bytes as hex")
    ->required();

  std::string policy_file;
  app.add_option(
    "--policy", policy_file, "Policy JSON file. Defaults to libcnap's default");

  std::string expected_measurement;
  app.add_option(
    "--expected-measurement",
    expected_measurement,
    "If given, fail unless MRTD equals this hex value");

  CLI11_PARSE(app, argc, argv);

  ccf::pal::tdx::CollateralConfig config{
    .bundle_dir = bundle_dir, .syncer_pubkey_hex = syncer_pubkey};
  if (!policy_file.empty())
  {
    config.policy_json = files::slurp_string(policy_file);
  }
  ccf::pal::tdx::set_collateral_config(config);

  ccf::QuoteInfo quote_info = {};
  quote_info.format = ccf::QuoteFormat::intel_tdx_v1;
  quote_info.quote = files::slurp(quote_file);

  ccf::pal::PlatformAttestationMeasurement measurement = {};
  ccf::pal::PlatformAttestationReportData report_data = {};

  try
  {
    ccf::pal::verify_quote(quote_info, measurement, report_data);
  }
  catch (const std::exception& e)
  {
    std::cout << "Verification failed: " << e.what() << '\n';
    return 1;
  }

  std::cout << "Verified Intel TDX attestation" << '\n';
  std::cout << "  MRTD        : " << measurement.hex_str() << '\n';
  std::cout << "  report_data : " << report_data.hex_str() << '\n';

  if (!expected_measurement.empty())
  {
    if (measurement.hex_str() != expected_measurement)
    {
      std::cout << "MRTD does not match expected " << expected_measurement
                << '\n';
      return 1;
    }
    std::cout << "  MRTD matches the expected value" << '\n';
  }

  return 0;
}
