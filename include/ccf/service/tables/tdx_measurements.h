// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/measurement.h"
#include "ccf/service/code_status.h"
#include "ccf/service/map.h"

namespace ccf
{
  // MRTD values a node is permitted to join with. The TDX analogue of
  // SnpMeasurements, kept as a separate table because MRTD is a different
  // measurement of a different thing, and a value approved for one platform
  // says nothing about the other.
  using TdxMeasurements =
    ServiceMap<pal::TdxAttestationMeasurement, CodeStatus>;

  namespace Tables
  {
    static constexpr auto NODE_TDX_MEASUREMENTS =
      "public:ccf.gov.nodes.tdx.measurements";
  }
}
