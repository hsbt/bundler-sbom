# Bundler SBOM Plugin

Generate and analyze Software Bill of Materials (SBOM) for your Ruby projects using Bundler.

## Installation

Install this plugin by running:

```
$ bundler plugin install bundler-sbom
```

## Usage

### Generate SBOM

To generate an SBOM file in SPDX format from your project's Gemfile.lock:

```
$ bundle sbom dump
```

This will create a `bom.json` file in your project directory.

### Analyze License Information

To view a summary of licenses used in your project's dependencies:

```
$ bundle sbom license
```

This command will show:
- A count of packages using each license
- A detailed list of packages grouped by license

Note: The `license` command requires that you've already generated the SBOM using `bundle sbom dump`.