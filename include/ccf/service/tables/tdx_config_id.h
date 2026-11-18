// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/measurement.h"
#include "ccf/service/map.h"

namespace ccf
{
  // The raw initdata document a config id is the digest of, when the consortium
  // chose to record it. Optional and purely for legibility: the security
  // property comes from the digest, not from this. Mirrors HostDataMetadata.
  using TdxConfigIdMetadata = std::string;

  // MRCONFIGID values a node is permitted to join with.
  //
  // Separate from SnpHostDataMap because MRCONFIGID is 48 bytes and HOST_DATA
  // is 32; a shared table would have to either widen HostData -- changing the
  // serialisation of two tables that existing ledgers already contain -- or
  // truncate a measurement to make it fit.
  using TdxConfigIdMap = ServiceMap<pal::TdxConfigId, TdxConfigIdMetadata>;

  namespace Tables
  {
    static constexpr auto NODE_TDX_CONFIG_ID =
      "public:ccf.gov.nodes.tdx.config_id";
  }
}
