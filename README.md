# Bundler SBOM Plugin

Generate and analyze Software Bill of Materials (SBOM) for your Ruby projects using Bundler.

## Installation

Install this plugin by running:

```
$ bundler plugin install bundler-sbom
```

## Usage

### Generate SBOM

To generate an SBOM file from your project's Gemfile.lock:

```
$ bundle sbom dump [options]
```

Available options:
- `-f, --format FORMAT`: Output format (json or xml, default: json)
- `-s, --sbom FORMAT`: SBOM specification format (spdx or cyclonedx, default: spdx)
- `--without GROUPS`: Exclude groups (comma or colon separated, e.g., 'development:test' or 'development,test')

Generated files will be named according to the following pattern:
- SPDX format: `bom.json` or `bom.xml`
- CycloneDX format: `bom-cyclonedx.json` or `bom-cyclonedx.xml`

Examples:
```
$ bundle sbom dump                           # Generates SPDX format in JSON (bom.json)
$ bundle sbom dump -f xml                    # Generates SPDX format in XML (bom.xml)
$ bundle sbom dump -s cyclonedx             # Generates CycloneDX format in JSON (bom-cyclonedx.json)
$ bundle sbom dump -s cyclonedx -f xml      # Generates CycloneDX format in XML (bom-cyclonedx.xml)
$ bundle sbom dump --without development    # Excludes development group
$ bundle sbom dump --without development:test  # Excludes development and test groups
```

### Analyze License Information

To view a summary of licenses used in your project's dependencies:

```
$ bundle sbom license [options]
```

Available options:
- `-f, --file PATH`: Input SBOM file path
- `-F, --format FORMAT`: Input format (json or xml)

If no options are specified, the command will automatically look for SBOM files in the following order:
1. `bom.xml` (if format is xml)
2. `bom-cyclonedx.json`
3. `bom-cyclonedx.xml`
4. `bom.json`

This command will show:
- A count of packages using each license
- A detailed list of packages grouped by license

Note: The `license` command requires that you've already generated the SBOM using `bundle sbom dump`.

## Supported SBOM Formats

### SPDX (v2.3)
[SPDX (Software Package Data Exchange)](https://spdx.dev/) is a standard format for communicating software bill of material information, including components, licenses, copyrights, and security references.

- Spec version: [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/)
- Output formats: JSON, XML
- License identifiers are validated against a curated subset of the [SPDX License List](https://spdx.org/licenses/). Identifiers not in this subset are treated as non-SPDX and output as `LicenseRef-` identifiers, and deprecated SPDX IDs (e.g., `GPL-2.0`) are mapped to their current equivalents (e.g., `GPL-2.0-only`).

### CycloneDX (v1.4)
[CycloneDX](https://cyclonedx.org/) is a lightweight SBOM specification designed for use in application security contexts and supply chain component analysis.

- Spec version: [CycloneDX 1.4](https://cyclonedx.org/docs/1.4/json/)
- Output formats: JSON, XML
- SPDX license IDs are placed in the `license.id` field, and non-SPDX licenses use the `license.name` field, per the CycloneDX specification.

## References

- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [About Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom)