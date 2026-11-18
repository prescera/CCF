// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <fstream>
#include <string>
#include <unistd.h>

namespace ccf::pal::tdx
{
  // The kernel's TSM report interface (configfs-tsm), through which a guest
  // asks for a quote. This is the same interface libcnap drives; CCF only ever
  // probes for its presence here, and never reads or writes a report itself.
  static constexpr auto TSM_REPORT_ROOT = "/sys/kernel/config/tsm/report";

  static inline bool has_tdx_guest_cpu_flag()
  {
    // /proc/cpuinfo advertises `tdx_guest` when the guest kernel has brought up
    // TDX support, which it does only inside a Trust Domain.
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo)
    {
      return false;
    }

    std::string line;
    while (std::getline(cpuinfo, line))
    {
      if (line.rfind("flags", 0) != 0)
      {
        continue;
      }
      // Match the whole token, so a hypothetical `tdx_guest_foo` does not read
      // as a match.
      for (size_t pos = line.find("tdx_guest"); pos != std::string::npos;
           pos = line.find("tdx_guest", pos + 1))
      {
        const auto end = pos + std::string_view("tdx_guest").size();
        const bool left_ok = pos == 0 || line[pos - 1] == ' ';
        const bool right_ok = end == line.size() || line[end] == ' ';
        if (left_ok && right_ok)
        {
          return true;
        }
      }
      return false;
    }
    return false;
  }

  static inline bool supports_tdx()
  {
    // Two conditions, and both are needed. configfs-tsm alone is not
    // TDX-specific -- SEV-SNP guests expose the same interface on recent
    // kernels
    // -- so it cannot identify the platform on its own. The `tdx_guest` CPU
    // flag is what says "this is a Trust Domain", and the writable TSM root is
    // what says quotes can actually be produced here rather than failing later
    // at startup.
    return has_tdx_guest_cpu_flag() && access(TSM_REPORT_ROOT, W_OK) == 0;
  }
}
