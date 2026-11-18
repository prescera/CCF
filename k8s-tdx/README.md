# Running a CCF node as `Platform::TDX`

Lab scaffolding for exercising the Intel TDX attestation path on real hardware.
Not a production deployment, and not intended for upstream — the CCF patch
itself is the deliverable; this is how it was verified.

## What it proves

A single CCF node inside a Kata Confidential Containers Trust Domain that
detects `Platform::TDX`, produces a real hardware quote through `configfs-tsm`,
and verifies that quote itself against a signed Intel collateral bundle before
opening the service.

```
Intel TDX: collateral bundle /opt/ccf-tdx/collateral
Intel TDX: generated quote, {"tee":"intel_tdx","provider":"configfs-tsm","size":5243}
Initial node attestation ("Intel_TDX_v1"): BAACAIEAAAAA...
Intel TDX: attestation verified. TCB status UpToDate, collateral epoch epoch-1
           (standard channel, TCB evaluation data number 20)
Created service
Network TLS connections now accepted
```

## Build

```bash
docker build -t ccf-build:al3 -f k8s-tdx/Dockerfile.build k8s-tdx/

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/src" -v /path/to/builddir:/build \
  -e CARGO_HOME=/build/.cargo -e HOME=/build -w /build ccf-build:al3 \
  sh -c 'cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF /src && \
         ninja js_generic verify_tdx_attestation'
```

`ninja` with no target fails on `tests/perf-system/submitter`, which needs
Apache Arrow — name the targets, or configure with `-DGLIBCXX_DEBUG=ON`.
The source mount must be writable: cmake generates `include/ccf/version.h`,
`src/host/config_schema.h` and `src/node/gov/api_schema.h` in place.

## Collateral bundle

The node appraises quotes against a locally supplied, signed bundle — Intel
collateral is per platform _model_ (FMSPC), not per node, so it is never carried
with the quote. In an air-gapped deployment the bundle arrives over a data
diode.

```bash
cnap-cli bundle-build \
  --collateral <FMSPC>=collateral-standard.json \
  --channel standard --out bundle --signing-key "$ED25519_HEX"
```

The printed public key goes into `attestation.tdx_collateral_syncer_pubkey`.
**The channel is a deployment decision that flips verdicts on identical
hardware**: on this platform the same quote is `UpToDate` on `standard` and
`OutOfDate` (7 advisories) on `early`. It lives in the policy file, and has no
safe default.

## Deploy

```bash
mkdir -p workspace && (cd workspace && \
  /path/to/CCF/python/utils/keygenerator.sh --name member0 --gen-enc-key)

# node image: cchost + constitution + collateral + node-config.json
docker build -t $REGISTRY/ccf-tdx:v4 -f k8s-tdx/Dockerfile <staging dir>
docker push $REGISTRY/ccf-tdx:v4

IMAGE=$REGISTRY/ccf-tdx:v4 WORKSPACE=$PWD/workspace ./k8s-tdx/render.sh
kubectl apply -f k8s-tdx/ccf-tdx.yaml
```

The member **private** key never enters the cluster; only `member0_cert.pem` and
`member0_enc_pubk.pem` do.

## Two things that will bite

**configfs is not mounted in the container.** `tdx_guest` is in `/proc/cpuinfo`
and `/sys/kernel/config` exists but is empty, so `/sys/kernel/config/tsm/report`
— the only way to request a quote — is absent and CCF silently falls back to
`Platform::Virtual`. The container mounts it itself under `CAP_SYS_ADMIN`; see
the comment in `render.sh`. That is privilege inside the guest VM, which is
inside the TEE, so the TD boundary is unaffected. Azure Linux's base image has
no `mount` — the node image installs `util-linux`.

**`kubectl port-forward` cannot reach a Kata pod.** It dials localhost in the
host network namespace while the listener is inside the guest VM. Use the pinned
service ClusterIP, which is why `render.sh` pins it: a known address before
startup can go into the node certificate SANs, so clients verify the service
certificate properly rather than falling back to `-k`.

## Two nodes, and what the join actually checks

`ccf-tdx-join.yaml` starts a second Trust Domain that joins the first. The
joining node's evidence is checked against the KV in three independent steps,
each of which the consortium governs:

| Check                                  | Table                            | Governance action     |
| -------------------------------------- | -------------------------------- | --------------------- |
| MRTD, the launch measurement           | `ccf.gov.nodes.tdx.measurements` | `add_tdx_measurement` |
| MRCONFIGID, the configuration identity | `ccf.gov.nodes.tdx.config_id`    | `add_tdx_config_id`   |
| Platform currency                      | `ccf.gov.nodes.tdx.tcb_policies` | `set_tdx_tcb_policy`  |

A second node built from the same image joins with no governance at all,
because the first node records its own MRTD and MRCONFIGID when it creates the
service.

Two addressing details, both of which produce confusing failures:

- **Give each node a distinct `node_to_node_interface.published_address`.**
  It defaults to the bind address, so two nodes both publish `0.0.0.0:8001` and
  the second is rejected with `NodeAlreadyExists` — after its attestation has
  already succeeded, which makes it look like an attestation problem.
- **The service must expose the node-to-node port**, not just the RPC port.

### The TCB floor is the check worth understanding

`set_tdx_tcb_policy` exists because on Intel TDX the endorsing collateral
travels _with_ the quote, supplied by the attester. Intel-signed collateral
cannot be forged, but a node could present older, still-valid collateral under
which its own platform still appraises as `UpToDate`. Verified on hardware:
with a floor of `minimum_tcb_evaluation_data_number: 9999`, a node whose own
appraisal says

```
Intel TDX: attestation verified. TCB status UpToDate, collateral epoch
           caller-supplied (standard channel, TCB evaluation data number 20)
```

is still refused by the primary:

```
Intel TDX: node was appraised against TCB evaluation data number 20,
           below the required minimum 9999
-> Join request returned 401: {"code":"InvalidQuote",
   "message":"Quote TCB version is too low"}
```

Lowering the floor to 20 lets the same node join. Without this table the
admission criteria would be whatever each node's own configuration said.

## Verifying a quote outside the node

`verify_tdx_attestation` runs CCF's own PAL against a quote and a bundle, with
no network and no TD required — useful for appraising a node's quote
independently, or for reproducing a verdict later.

```bash
verify_tdx_attestation --quote quote.bin --bundle bundle --key <syncer pubkey hex>
```
