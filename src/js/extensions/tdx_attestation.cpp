// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/tdx_attestation.h"

#include "ccf/ds/hex.h"
#include "ccf/js/core/context.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_tdx.h"
#include "js/checks.h"

#include <quickjs/quickjs.h>
#include <vector>

namespace ccf::js::extensions
{
  namespace
  {
    // tdx_attestation.verifyTdxAttestation(quote, endorsements)
    //
    //   quote        ArrayBuffer, the raw TDX quote
    //   endorsements ArrayBuffer, the collateral envelope that travelled with
    //                it. Optional: when omitted, the node's own locally
    //                configured collateral bundle is used instead, which is
    //                only meaningful for a peer on the same platform model.
    //
    // Returns the verified claims. Throws if the quote is not authentic or its
    // TCB does not satisfy the node's configured hardware policy.
    //
    // Deciding whether the returned measurements are the *approved* ones is the
    // caller's job -- that is a policy question, and keeping it out of here is
    // what lets an application express its own release policy over these
    // claims.
    JSValue js_verify_tdx_attestation(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc < 1 || argc > 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1 or 2", argc);
      }
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      size_t quote_size = 0;
      uint8_t* quote = JS_GetArrayBuffer(ctx, &quote_size, argv[0]);
      if (quote == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }

      std::vector<uint8_t> endorsements;
      if (argc >= 2 && JS_IsUndefined(argv[1]) == 0)
      {
        size_t endorsements_size = 0;
        uint8_t* endorsements_array =
          JS_GetArrayBuffer(ctx, &endorsements_size, argv[1]);
        if (endorsements_array == nullptr)
        {
          return ccf::js::core::constants::Exception;
        }
        endorsements.assign(
          endorsements_array, endorsements_array + endorsements_size);
      }

      QuoteInfo quote_info = {};
      quote_info.format = QuoteFormat::intel_tdx_v1;
      quote_info.quote = std::vector<uint8_t>(quote, quote + quote_size);
      quote_info.endorsements = std::move(endorsements);

      pal::tdx::Verdict verdict;
      try
      {
        verdict = pal::tdx::verify(quote_info);
      }
      catch (const std::exception& e)
      {
        return JS_ThrowRangeError(
          ctx, "Failed to verify Intel TDX attestation: %s", e.what());
      }

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);

      // Field names match what libcnap emits, so a release policy written
      // against a verdict reads the same whether it came from here or from the
      // CLI.
      auto launch_measurement =
        jsctx.new_string(verdict.launch_measurement.hex_str());
      JS_CHECK_EXC(launch_measurement);
      JS_CHECK_SET(r.set("launch_measurement", std::move(launch_measurement)));

      auto config_id = jsctx.new_string(verdict.config_id.hex_str());
      JS_CHECK_EXC(config_id);
      JS_CHECK_SET(r.set("config_id", std::move(config_id)));

      auto report_data = jsctx.new_string(ccf::ds::to_hex(verdict.report_data));
      JS_CHECK_EXC(report_data);
      JS_CHECK_SET(r.set("report_data", std::move(report_data)));

      auto rtmrs = jsctx.new_array();
      JS_CHECK_EXC(rtmrs);
      for (size_t i = 0; i < verdict.runtime_measurements.size(); ++i)
      {
        auto rtmr =
          jsctx.new_string(ccf::ds::to_hex(verdict.runtime_measurements[i]));
        JS_CHECK_EXC(rtmr);
        JS_CHECK_SET(rtmrs.set_at_index(i, std::move(rtmr)));
      }
      JS_CHECK_SET(r.set("runtime_measurements", std::move(rtmrs)));

      auto tcb_status = jsctx.new_string(verdict.tcb_status);
      JS_CHECK_EXC(tcb_status);
      JS_CHECK_SET(r.set("tcb_status", std::move(tcb_status)));

      auto tcb_channel = jsctx.new_string(verdict.tcb_channel);
      JS_CHECK_EXC(tcb_channel);
      JS_CHECK_SET(r.set("tcb_channel", std::move(tcb_channel)));

      auto fmspc = jsctx.new_string(verdict.fmspc);
      JS_CHECK_EXC(fmspc);
      JS_CHECK_SET(r.set("fmspc", std::move(fmspc)));

      JS_CHECK_SET(r.set_int64(
        "tcb_evaluation_data_number",
        static_cast<int64_t>(verdict.tcb_evaluation_data_number)));
      JS_CHECK_SET(r.set_bool("degraded", verdict.degraded));

      auto advisories = jsctx.new_array();
      JS_CHECK_EXC(advisories);
      for (size_t i = 0; i < verdict.advisory_ids.size(); ++i)
      {
        auto id = jsctx.new_string(verdict.advisory_ids[i]);
        JS_CHECK_EXC(id);
        JS_CHECK_SET(advisories.set_at_index(i, std::move(id)));
      }
      JS_CHECK_SET(r.set("advisory_ids", std::move(advisories)));

      return r.take();
    }
  }

  void TdxAttestationExtension::install(js::core::Context& ctx)
  {
    auto tdx_attestation = ctx.new_obj();

    JS_CHECK_OR_THROW(tdx_attestation.set(
      "verifyTdxAttestation",
      ctx.new_c_function(
        js_verify_tdx_attestation, "verifyTdxAttestation", 2)));

    auto global_obj = ctx.get_global_obj();
    JS_CHECK_OR_THROW(
      global_obj.set("tdx_attestation", std::move(tdx_attestation)));
  }
}
