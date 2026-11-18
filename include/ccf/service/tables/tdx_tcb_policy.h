// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"

#include <string>
#include <vector>

namespace ccf
{
  // The consortium's floor on how current a joining TDX node's platform must
  // be.
  //
  // This exists because on Intel TDX the endorsing collateral is supplied to
  // each node rather than fetched from the vendor per quote, and a node may
  // present the collateral it was given. Intel-signed collateral cannot be
  // forged, but an operator could hold their node at an older, still-valid
  // epoch under which their platform still appraises as UpToDate. Without a
  // floor recorded here, each node's own configuration would decide how current
  // it has to be, which is the operator deciding their own admission criteria.
  //
  // The SEV-SNP counterpart is SnpTcbVersionMap. It is keyed by CPUID because
  // AMD's TCB is a per-product version tuple; Intel's is a per-FMSPC evaluation
  // number plus a status, so the shape differs.
  struct TdxTcbPolicy
  {
    // Minimum acceptable tcbEvaluationDataNumber. Intel increments this on
    // every TCB recovery, so it is monotonic and is the meaningful floor: it
    // says "collateral at least this recent", which a status string cannot.
    uint32_t minimum_tcb_evaluation_data_number = 0;

    // TCB statuses a joining node may present. Empty means UpToDate only.
    // Deliberately not defaulted to something permissive: accepting
    // OutOfDate should be a recorded decision, not a fallback.
    std::vector<std::string> accepted_tcb_statuses = {};

    // The collateral channel a joining node must have been appraised against,
    // "standard" or "early". The same quote can be UpToDate on one and
    // OutOfDate on the other, so leaving this to each node would let a node
    // pick the channel that flatters it.
    std::string tcb_channel = "standard";

    bool operator==(const TdxTcbPolicy&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TdxTcbPolicy);
  DECLARE_JSON_REQUIRED_FIELDS(TdxTcbPolicy);
  DECLARE_JSON_OPTIONAL_FIELDS(
    TdxTcbPolicy,
    minimum_tcb_evaluation_data_number,
    accepted_tcb_statuses,
    tcb_channel);

  // Keyed by FMSPC (12 hex characters), which identifies a platform model and
  // configuration, because that is the granularity Intel publishes collateral
  // at. The empty key is the default applied to any FMSPC without its own
  // entry.
  using TdxTcbPolicyMap = ServiceMap<std::string, TdxTcbPolicy>;

  namespace Tables
  {
    static constexpr auto TDX_TCB_POLICIES =
      "public:ccf.gov.nodes.tdx.tcb_policies";
  }
}
