// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - tdx_attestation.verifyTdxAttestation
   *
   * The Intel TDX counterpart of SnpAttestationExtension. An application needs
   * this to appraise a *peer's* attestation from inside its own endpoint logic
   * -- a key management service deciding whether to release a secret, for
   * instance. It is distinct from the node's own attestation, which the
   * framework handles during startup and joining.
   **/
  class TdxAttestationExtension : public ExtensionInterface
  {
  public:
    TdxAttestationExtension() = default;

    void install(js::core::Context& ctx) override;
  };
}
