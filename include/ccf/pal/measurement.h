// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <array>
#include <span>
#include <type_traits>

namespace ccf::pal
{
  template <size_t N, typename Tag = void>
  struct AttestationMeasurement
  {
    std::array<uint8_t, N> measurement;

    static size_t size()
    {
      return N;
    }

    [[nodiscard]] std::string hex_str() const
    {
      return ds::to_hex(measurement);
    }

    AttestationMeasurement() = default;
    AttestationMeasurement(const std::string& hex_str)
    {
      ds::from_hex(hex_str, measurement);
    }
    AttestationMeasurement(std::span<const uint8_t> data)
    {
      if (data.size() != size())
      {
        throw std::logic_error(fmt::format(
          "Cannot initialise AttestationMeasurement with data of size {}, "
          "expected {}",
          data.size(),
          size()));
      }

      std::copy(data.data(), data.data() + data.size(), measurement.data());
    }
  };

  template <typename>
  struct is_attestation_measurement : std::false_type
  {};

  template <size_t N, typename Tag>
  struct is_attestation_measurement<AttestationMeasurement<N, Tag>>
    : std::true_type
  {};

  template <size_t N, typename Tag = void>
  inline void to_json(
    nlohmann::json& j, const AttestationMeasurement<N, Tag>& measurement)
  {
    j = measurement.hex_str();
  }

  template <size_t N, typename Tag = void>
  inline void from_json(
    const nlohmann::json& j, AttestationMeasurement<N, Tag>& measurement)
  {
    if (j.is_string())
    {
      measurement = j.get<std::string>();
    }
    else
    {
      throw ccf::JsonParseError(fmt::format(
        "Attestation measurement should be hex-encoded string: {}", j.dump()));
    }
  }

  template <size_t N, typename Tag = void>
  inline void fill_json_schema(
    nlohmann::json& schema,
    [[maybe_unused]] const AttestationMeasurement<N, Tag>* measurement_type)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
    schema["pattern"] =
      fmt::format("^[a-f0-9]{}$", AttestationMeasurement<N, Tag>::size() * 2);
  }

  // Virtual
  using VirtualAttestationMeasurement = std::string;

  // SGX
  static constexpr size_t sgx_attestation_measurement_size = 32;
  using SgxAttestationMeasurement =
    AttestationMeasurement<sgx_attestation_measurement_size>;

  inline std::string schema_name(
    [[maybe_unused]] const SgxAttestationMeasurement* sgx_measurement_type)
  {
    return "SgxAttestationMeasurement";
  }

  // SNP
  static constexpr size_t snp_attestation_measurement_size = 48;
  using SnpAttestationMeasurement =
    AttestationMeasurement<snp_attestation_measurement_size>;

  inline std::string schema_name(
    [[maybe_unused]] const SnpAttestationMeasurement* snp_measurement_type)
  {
    return "SnpAttestationMeasurement";
  }

  // TDX
  // MRTD, the launch measurement of the Trust Domain: SHA-384 over the initial
  // memory image, and so the TDX analogue of the SNP launch measurement. The
  // configuration a TD was launched under is measured separately, into
  // MRCONFIGID, and is not this value.
  static constexpr size_t tdx_attestation_measurement_size = 48;
  using TdxAttestationMeasurement =
    AttestationMeasurement<tdx_attestation_measurement_size, struct TdxTag>;

  inline std::string schema_name(
    [[maybe_unused]] const TdxAttestationMeasurement* tdx_measurement_type)
  {
    return "TdxAttestationMeasurement";
  }

  // TDX MRCONFIGID: the settable launch configuration claim, SHA-384. On Kata
  // Confidential Containers it is the digest of the TD's initdata document.
  //
  // This is the TDX counterpart of SEV-SNP's HOST_DATA, but it is 48 bytes
  // where HOST_DATA is 32, so it cannot share the `HostData` (Sha256Hash) type.
  // It gets its own type and its own KV table, which is the same shape the
  // per-platform measurement tables already have.
  static constexpr size_t tdx_config_id_size = 48;
  using TdxConfigId =
    AttestationMeasurement<tdx_config_id_size, struct TdxConfigIdTag>;

  inline std::string schema_name(
    [[maybe_unused]] const TdxConfigId* tdx_config_id_type)
  {
    return "TdxConfigId";
  }

  // Generic wrapper for code digests on all TEE platforms
  struct PlatformAttestationMeasurement
  {
    std::vector<uint8_t> data;

    PlatformAttestationMeasurement() = default;
    PlatformAttestationMeasurement(const PlatformAttestationMeasurement&) =
      default;

    template <size_t N, typename Tag>
    PlatformAttestationMeasurement(
      const AttestationMeasurement<N, Tag>& measurement) :
      data(measurement.measurement.begin(), measurement.measurement.end())
    {}

    PlatformAttestationMeasurement& operator=(
      const PlatformAttestationMeasurement&) = default;

    [[nodiscard]] std::string hex_str() const
    {
      return ds::to_hex(data);
    }

    operator std::span<const uint8_t>() const
    {
      return data;
    }
  };
  DECLARE_JSON_TYPE(PlatformAttestationMeasurement);
  DECLARE_JSON_REQUIRED_FIELDS(PlatformAttestationMeasurement, data);
}

namespace ccf::kv::serialisers
{
  template <size_t N, typename Tag>
  struct BlitSerialiser<ccf::pal::AttestationMeasurement<N, Tag>>
  {
    static SerialisedEntry to_serialised(
      const ccf::pal::AttestationMeasurement<N, Tag>& measurement)
    {
      auto hex_str = measurement.hex_str();
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::pal::AttestationMeasurement<N, Tag> from_serialised(
      const SerialisedEntry& data)
    {
      ccf::pal::AttestationMeasurement<N, Tag> ret{};
      ccf::ds::from_hex(std::string(data.data(), data.end()), ret.measurement);
      return ret;
    }
  };
}