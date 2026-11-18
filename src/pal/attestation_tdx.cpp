// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// The Intel TDX attestation shim.
//
// Everything TDX-specific -- quote parsing, the PCK certificate chain, CRLs,
// TCB Info and QE Identity appraisal, the SGX PKI a TDX quote is signed under,
// and the collateral bundle format -- lives in libcnap, behind the C ABI
// declared in <cnap/cnap.h>. This file translates between that ABI and CCF's
// platform abstraction, and does nothing else. It deliberately contains no
// knowledge of the quote layout: if a claim is needed, it is read from the
// verdict libcnap returns, not parsed out of the quote here.

#include "ccf/pal/attestation_tdx.h"

#include "ccf/ds/hex.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "ds/internal_logger.h"

#include <cnap/cnap.h>
#include <memory>
#include <nlohmann/json.hpp>

namespace ccf::pal
{
  namespace
  {
    // libcnap allocates through Rust's allocator, so its returns must be
    // released through its own free functions and no others.
    struct CnapString
    {
      char* p = nullptr;
      ~CnapString()
      {
        cnap_string_free(p);
      }
      CnapString() = default;
      CnapString(const CnapString&) = delete;
      CnapString& operator=(const CnapString&) = delete;

      [[nodiscard]] std::string view() const
      {
        return p == nullptr ? std::string{} : std::string(p);
      }
    };

    struct CnapBytes
    {
      uint8_t* p = nullptr;
      size_t len = 0;
      ~CnapBytes()
      {
        cnap_bytes_free(p, len);
      }
      CnapBytes() = default;
      CnapBytes(const CnapBytes&) = delete;
      CnapBytes& operator=(const CnapBytes&) = delete;
    };

    std::optional<tdx::CollateralConfig>& collateral_config()
    {
      static std::optional<tdx::CollateralConfig> config = std::nullopt;
      return config;
    }

    const tdx::CollateralConfig& require_collateral_config()
    {
      const auto& config = collateral_config();
      if (!config.has_value())
      {
        // Failing here is the point. Without collateral there is no way to tell
        // a current platform from one with published vulnerabilities, and a
        // quote that was not appraised must not be mistaken for one that
        // passed.
        throw std::logic_error(
          "Intel TDX: no collateral configuration set. Set "
          "attestation.tdx_collateral_bundle_dir and "
          "attestation.tdx_collateral_syncer_pubkey in the node "
          "configuration.");
      }
      return config.value();
    }

    struct Endorsements
    {
      std::string collateral_json;
      std::string channel;
    };

    // Unpack the envelope cnap_bundle_export_collateral() produced. The channel
    // has to travel with the collateral because it is a parameter to Intel's
    // API rather than a field in the response, so it cannot be recovered from
    // the document itself -- and the two channels legitimately disagree about
    // the same platform.
    Endorsements parse_endorsements(const std::vector<uint8_t>& raw)
    {
      nlohmann::json envelope;
      try
      {
        envelope = nlohmann::json::parse(raw.begin(), raw.end());
      }
      catch (const std::exception& e)
      {
        throw std::logic_error(fmt::format(
          "Intel TDX: endorsements are not valid JSON: {}", e.what()));
      }

      const auto collateral = envelope.find("collateral");
      const auto channel = envelope.find("channel");
      if (
        collateral == envelope.end() || channel == envelope.end() ||
        !channel->is_string())
      {
        throw std::logic_error(
          "Intel TDX: endorsements must carry both a `collateral` document and "
          "the `channel` it was published on");
      }

      return {collateral->dump(), channel->get<std::string>()};
    }

    // Take the collateral that endorses this quote out of the local bundle, so
    // it can travel with the quote.
    //
    // Without this, a TDX node's attestation would only be verifiable by
    // someone who happened to hold collateral for its platform model, and only
    // until that collateral expired. Recording it alongside the quote is what
    // makes a node's attestation self-contained in the ledger -- the property
    // SEV-SNP gets for free, because its endorsement chain is already carried
    // in the report.
    std::vector<uint8_t> export_collateral_for(
      const std::vector<uint8_t>& quote)
    {
      const auto& config = require_collateral_config();

      CnapString out;
      const auto rc = cnap_bundle_export_collateral(
        quote.data(),
        quote.size(),
        config.bundle_dir.c_str(),
        config.syncer_pubkey_hex.c_str(),
        config.policy_json.has_value() ? config.policy_json->c_str() : nullptr,
        &out.p);

      if (rc != CNAP_OK)
      {
        // Fatal, and fatal early: a node whose bundle does not cover its own
        // platform cannot verify its own quote either, so it would fail a
        // moment later with a less obvious message.
        throw std::logic_error(fmt::format(
          "Intel TDX: could not export the collateral endorsing this node's "
          "own quote (cnap rc {}): {}",
          rc,
          out.view()));
      }

      const auto envelope = out.view();
      return {envelope.begin(), envelope.end()};
    }

    // Pull a hex-encoded claim of an exact expected length out of the verdict.
    std::vector<uint8_t> claim_bytes(
      const nlohmann::json& claims,
      const std::string& name,
      size_t expected_len)
    {
      auto it = claims.find(name);
      if (it == claims.end() || !it->is_string())
      {
        throw std::logic_error(fmt::format(
          "Intel TDX: verdict claim '{}' is missing or not a hex string",
          name));
      }

      const auto hex = it->get<std::string>();
      if (hex.size() != expected_len * 2)
      {
        throw std::logic_error(fmt::format(
          "Intel TDX: verdict claim '{}' is {} hex characters, expected {}",
          name,
          hex.size(),
          expected_len * 2));
      }

      return ccf::ds::from_hex(hex);
    }

    // Summarise a verdict for the node log. A verdict is the audit trail for a
    // trust decision, so the interesting parts are recorded even on success --
    // in particular any degradation, which means a grace window let evidence
    // pass that would otherwise have been rejected.
    void log_verdict(const nlohmann::json& verdict)
    {
      const auto tcb_status = verdict.value("tcb_status", "unknown");
      const auto& collateral = verdict["collateral"];

      LOG_INFO_FMT(
        "Intel TDX: attestation verified. TCB status {}, collateral epoch {} "
        "({} channel, TCB evaluation data number {}), expires at {}",
        tcb_status,
        collateral.value("source", "unknown"),
        collateral.value("channel", "unknown"),
        collateral.value("tcb_eval_data_number", 0),
        collateral.value("expires_at", 0));

      const auto advisories = verdict.find("advisory_ids");
      if (advisories != verdict.end() && !advisories->empty())
      {
        LOG_INFO_FMT(
          "Intel TDX: platform carries advisories {}", advisories->dump());
      }

      const auto degradations = verdict.find("degradations");
      if (degradations != verdict.end() && !degradations->empty())
      {
        // Not a failure, but never silent: a configured relaxation was applied,
        // and whoever audits this node needs to see it.
        LOG_FAIL_FMT(
          "Intel TDX: attestation passed only because a grace window applied: "
          "{}",
          degradations->dump());
      }
    }
  }

  namespace tdx
  {
    void set_collateral_config(const CollateralConfig& config)
    {
      collateral_config() = config;
    }

    bool has_collateral_config()
    {
      return collateral_config().has_value();
    }

    void generate_tdx_quote(
      PlatformAttestationReportData& report_data,
      RetrieveEndorsementCallback endorsement_cb)
    {
      // TDX report_data is 64 bytes. CCF supplies the SHA-256 of the node's
      // public key, 32 bytes, and pads the rest -- the same convention as the
      // SEV-SNP path, and what verify_quoted_node_public_key() checks against
      // later.
      //
      // Note this is deliberately *not* libcnap's binding profile v1, which
      // splits report_data into a verifier-chosen nonce half and a session-key
      // half. CCF has its own binding convention and no nonce at this point in
      // startup, so cnap_generate_quote() is used rather than cnap_attest(),
      // and the binding is checked by CCF rather than by libcnap.
      std::array<uint8_t, tdx_attestation_report_data_size> padded{};
      if (report_data.data.size() > padded.size())
      {
        throw std::logic_error(fmt::format(
          "Intel TDX: report data is {} bytes, larger than the {} available",
          report_data.data.size(),
          padded.size()));
      }
      std::copy(
        report_data.data.begin(), report_data.data.end(), padded.begin());

      CnapBytes quote;
      CnapString meta;
      const auto rc = cnap_generate_quote(
        padded.data(), padded.size(), &quote.p, &quote.len, &meta.p);
      if (rc != CNAP_OK)
      {
        // libcnap distinguishes "configfs is not mounted in this container"
        // from "this is not a confidential guest", which are different things
        // to fix, so its diagnosis is surfaced rather than replaced.
        throw std::logic_error(fmt::format(
          "Intel TDX: quote generation failed (cnap rc {}): {}",
          rc,
          meta.view()));
      }

      LOG_INFO_FMT("Intel TDX: generated quote, {}", meta.view());

      QuoteInfo node_quote_info = {};
      node_quote_info.format = QuoteFormat::intel_tdx_v1;
      node_quote_info.quote.assign(quote.p, quote.p + quote.len);
      node_quote_info.endorsements =
        export_collateral_for(node_quote_info.quote);

      // No endorsement server round trip: unlike SEV-SNP, the endorsements were
      // already on this node's disk. The callback is invoked immediately so the
      // startup path is the same shape on both platforms.
      if (endorsement_cb != nullptr)
      {
        endorsement_cb(node_quote_info, {});
      }
    }
  }

  namespace tdx
  {
    Verdict verify(const QuoteInfo& quote_info)
    {
      if (quote_info.format != QuoteFormat::intel_tdx_v1)
      {
        throw std::logic_error(fmt::format(
          "Unexpected attestation report to verify for Intel TDX: {}",
          quote_info.format));
      }

      const auto& config = require_collateral_config();
      const char* policy =
        config.policy_json.has_value() ? config.policy_json->c_str() : nullptr;

      CnapString out;
      int32_t rc = 0;

      if (quote_info.endorsements.empty())
      {
        // No endorsements travelling with the quote, so appraise it against
        // this node's own bundle. This is the path for a quote produced before
        // endorsements were carried, and for any caller that deliberately
        // supplies only a quote.
        rc = cnap_verify_quote(
          quote_info.quote.data(),
          quote_info.quote.size(),
          config.bundle_dir.c_str(),
          config.syncer_pubkey_hex.c_str(),
          policy,
          // No binding: CCF binds the quote to the node's identity through
          // report_data, and checks that itself in
          // verify_quoted_node_public_key().
          nullptr,
          // Zero means "use the system clock". CCF has no better instant to
          // offer here; re-appraising archived evidence as of a past instant is
          // a separate concern, and is why the collateral is recorded at all.
          0,
          &out.p);
      }
      else
      {
        // Endorsements came with the quote. Preferring them is what lets a node
        // verify a peer whose platform model it has never synced collateral
        // for, and what lets this same evidence be re-appraised later from the
        // ledger alone.
        //
        // The collateral is Intel-signed and chains to a pinned root, so an
        // attester cannot forge it. It could still present older, genuinely
        // valid collateral under which its platform looks more current than it
        // is -- which is why the consortium's TCB floor is checked separately,
        // against the KV, in verify_tcb_version_against_store().
        const auto envelope = parse_endorsements(quote_info.endorsements);

        rc = cnap_verify_quote_with_collateral(
          quote_info.quote.data(),
          quote_info.quote.size(),
          envelope.collateral_json.c_str(),
          envelope.channel.c_str(),
          policy,
          nullptr,
          0,
          &out.p);
      }

      if (rc != CNAP_OK)
      {
        // CNAP_OK is returned only when a verdict exists *and* is trusted, so
        // any other code is a rejection. The verdict, when there is one, names
        // the check that failed.
        throw std::logic_error(fmt::format(
          "Intel TDX: attestation verification failed (cnap rc {}): {}",
          rc,
          out.view()));
      }

      const auto parsed = nlohmann::json::parse(out.view());
      const auto& claims = parsed.at("claims");
      const auto& collateral = parsed.at("collateral");

      log_verdict(parsed);

      Verdict verdict;
      verdict.launch_measurement = TdxAttestationMeasurement(claim_bytes(
        claims, "launch_measurement", tdx_attestation_measurement_size));
      verdict.config_id =
        TdxConfigId(claim_bytes(claims, "config_id", tdx_config_id_size));
      verdict.report_data =
        claim_bytes(claims, "report_data", tdx_attestation_report_data_size);
      const auto rtmrs = claims.find("runtime_measurements");
      if (rtmrs == claims.end() || !rtmrs->is_array() || rtmrs->size() != 4)
      {
        throw std::logic_error(
          "Intel TDX: verdict claim 'runtime_measurements' is not four RTMRs");
      }
      for (const auto& rtmr : *rtmrs)
      {
        if (
          !rtmr.is_string() ||
          rtmr.get<std::string>().size() !=
            tdx_attestation_measurement_size * 2)
        {
          throw std::logic_error(
            "Intel TDX: an RTMR in the verdict is not a 48-byte hex string");
        }
        verdict.runtime_measurements.push_back(
          ccf::ds::from_hex(rtmr.get<std::string>()));
      }

      verdict.tcb_status = parsed.value("tcb_status", "");
      verdict.tcb_evaluation_data_number =
        collateral.value("tcb_eval_data_number", 0);
      verdict.tcb_channel = collateral.value("channel", "");

      const auto platform_id = claims.find("platform_id");
      if (platform_id != claims.end())
      {
        verdict.fmspc = platform_id->value("fmspc", "");
      }

      const auto advisories = parsed.find("advisory_ids");
      if (advisories != parsed.end())
      {
        verdict.advisory_ids = advisories->get<std::vector<std::string>>();
      }

      const auto degradations = parsed.find("degradations");
      verdict.degraded = degradations != parsed.end() && !degradations->empty();

      return verdict;
    }
  }

  void verify_tdx_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    const auto verdict = tdx::verify(quote_info);
    measurement = verdict.launch_measurement;
    report_data = TdxAttestationReportData(verdict.report_data);
  }
}
