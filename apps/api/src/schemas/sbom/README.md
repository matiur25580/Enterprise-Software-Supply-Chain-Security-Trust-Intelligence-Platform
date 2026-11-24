# SBOM JSON schema sources

ChainProof vendors the upstream JSON schemas used for server-side SBOM validation.

| Schema | Upstream source | Upstream revision |
|---|---|---|
| CycloneDX 1.4 | https://github.com/CycloneDX/specification/blob/master/schema/bom-1.4.schema.json | master |
| CycloneDX 1.5 | https://github.com/CycloneDX/specification/blob/master/schema/bom-1.5.schema.json | master |
| CycloneDX 1.6 | https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json | master |
| CycloneDX SPDX extension | https://github.com/CycloneDX/specification/blob/master/schema/spdx.schema.json | master |
| CycloneDX JSF signature schema | https://github.com/CycloneDX/specification/blob/master/schema/jsf-0.82.schema.json | master |
| SPDX 2.3 | https://github.com/spdx/spdx-spec/blob/develop/schemas/spdx-schema.json | develop |

The CycloneDX schemas are distributed under Apache License 2.0. The SPDX schema is maintained by the SPDX project; see the upstream repository's license and contribution terms. Keep these files synchronized with an explicitly reviewed upstream revision. Do not silently replace a schema during routine dependency updates.
