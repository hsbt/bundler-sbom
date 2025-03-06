require "spec_helper"

RSpec.describe Bundler::Sbom::Reporter do
  let(:sample_sbom) do
    {
      "packages" => [
        { "name" => "rake", "licenseDeclared" => "MIT", "versionInfo" => "13.0.6" },
        { "name" => "rspec", "licenseDeclared" => "MIT", "versionInfo" => "3.12.0" },
        { "name" => "bundler", "licenseDeclared" => "MIT, Apache-2.0", "versionInfo" => "2.4.0" }
      ]
    }
  end

  let(:empty_sbom) do
    { "packages" => [] }
  end

  let(:no_license_sbom) do
    {
      "packages" => [
        { "name" => "unknown", "licenseDeclared" => "NOASSERTION", "versionInfo" => "1.0.0" }
      ]
    }
  end

  # CycloneDX format tests
  let(:cyclonedx_sample_sbom) do
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:example",
      "version" => 1,
      "metadata" => {
        "timestamp" => "2023-01-01T00:00:00Z",
        "tools" => [
          {
            "vendor" => "Bundler",
            "name" => "bundle-sbom",
            "version" => "0.1.0"
          }
        ],
        "component" => {
          "type" => "application",
          "name" => "test-app",
          "version" => "0.0.0"
        }
      },
      "components" => [
        {
          "type" => "library",
          "name" => "rake",
          "version" => "13.0.6",
          "purl" => "pkg:gem/rake@13.0.6",
          "licenses" => [
            { "license" => { "id" => "MIT" } }
          ]
        },
        {
          "type" => "library",
          "name" => "rspec",
          "version" => "3.12.0",
          "purl" => "pkg:gem/rspec@3.12.0",
          "licenses" => [
            { "license" => { "id" => "MIT" } }
          ]
        },
        {
          "type" => "library",
          "name" => "bundler",
          "version" => "2.4.0",
          "purl" => "pkg:gem/bundler@2.4.0",
          "licenses" => [
            { "license" => { "id" => "MIT" } },
            { "license" => { "id" => "Apache-2.0" } }
          ]
        }
      ]
    }
  end

  let(:cyclonedx_empty_sbom) do
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:example",
      "version" => 1,
      "metadata" => {
        "timestamp" => "2023-01-01T00:00:00Z",
        "tools" => [],
        "component" => {
          "type" => "application",
          "name" => "test-app",
          "version" => "0.0.0"
        }
      },
      "components" => []
    }
  end

  let(:cyclonedx_no_license_sbom) do
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:example",
      "version" => 1,
      "metadata" => {
        "timestamp" => "2023-01-01T00:00:00Z",
        "tools" => [],
        "component" => {
          "type" => "application",
          "name" => "test-app",
          "version" => "0.0.0"
        }
      },
      "components" => [
        {
          "type" => "library",
          "name" => "unknown",
          "version" => "1.0.0",
          "purl" => "pkg:gem/unknown@1.0.0"
        }
      ]
    }
  end

  describe ".analyze_licenses" do
    it "correctly counts license occurrences" do
      license_count = described_class.analyze_licenses(sample_sbom)
      expect(license_count["MIT"]).to eq(3)
      expect(license_count["Apache-2.0"]).to eq(1)
    end

    it "handles packages with no license" do
      license_count = described_class.analyze_licenses(no_license_sbom)
      expect(license_count["NOASSERTION"]).to eq(1)
    end

    context "when sbom has no packages" do
      it "returns empty hash" do
        expect(described_class.analyze_licenses(empty_sbom)).to be_empty
      end
    end
  end

  describe ".display_license_report" do
    it "outputs formatted license report" do
      output = StringIO.new
      allow($stdout).to receive(:puts) { |msg| output.puts(msg) }

      described_class.display_license_report(sample_sbom)
      report = output.string

      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("MIT: 3 package(s)")
      expect(report).to include("Apache-2.0: 1 package(s)")
      expect(report).to include("rake (13.0.6)")
      expect(report).to include("rspec (3.12.0)")
      expect(report).to include("bundler (2.4.0)")
    end

    it "handles packages with no declared license" do
      output = StringIO.new
      allow($stdout).to receive(:puts) { |msg| output.puts(msg) }

      described_class.display_license_report(no_license_sbom)
      report = output.string

      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("Total packages: 1")
      expect(report).to include("NOASSERTION: 1 package(s)")
      expect(report).to include("unknown (1.0.0)")
    end

    context "when sbom has no packages" do
      it "displays empty report" do
        output = StringIO.new
        allow($stdout).to receive(:puts) { |msg| output.puts(msg) }

        described_class.display_license_report(empty_sbom)
        report = output.string

        expect(report).to include("=== License Usage in SBOM ===")
        expect(report).to include("Total packages: 0")
      end
    end
  end

  describe ".sbom_format" do
    it "correctly detects CycloneDX format" do
      expect(described_class.sbom_format(cyclonedx_sample_sbom)).to eq(:cyclonedx)
    end

    it "defaults to SPDX format" do
      expect(described_class.sbom_format(sample_sbom)).to eq(:spdx)
    end
  end

  describe ".convert_cyclonedx_to_report_format" do
    it "correctly converts CycloneDX format to reporter format" do
      converted = described_class.convert_cyclonedx_to_report_format(cyclonedx_sample_sbom)
      expect(converted["packages"].size).to eq(3)
      
      rake_pkg = converted["packages"].find { |p| p["name"] == "rake" }
      expect(rake_pkg["versionInfo"]).to eq("13.0.6")
      expect(rake_pkg["licenseDeclared"]).to eq("MIT")
      
      bundler_pkg = converted["packages"].find { |p| p["name"] == "bundler" }
      expect(bundler_pkg["versionInfo"]).to eq("2.4.0")
      expect(bundler_pkg["licenseDeclared"]).to eq("MIT, Apache-2.0")
    end

    it "handles missing licenses in CycloneDX format" do
      converted = described_class.convert_cyclonedx_to_report_format(cyclonedx_no_license_sbom)
      expect(converted["packages"].size).to eq(1)
      expect(converted["packages"][0]["licenseDeclared"]).to eq("NOASSERTION")
    end
    
    it "handles empty components array" do
      converted = described_class.convert_cyclonedx_to_report_format(cyclonedx_empty_sbom)
      expect(converted["packages"]).to be_empty
    end
  end

  describe ".display_license_report with CycloneDX format" do
    it "outputs formatted license report from CycloneDX data" do
      output = StringIO.new
      allow($stdout).to receive(:puts) { |msg| output.puts(msg) }
      
      described_class.display_license_report(cyclonedx_sample_sbom)
      report = output.string
      
      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("MIT: 3 package(s)")
      expect(report).to include("Apache-2.0: 1 package(s)")
      expect(report).to include("rake (13.0.6)")
      expect(report).to include("rspec (3.12.0)")
      expect(report).to include("bundler (2.4.0)")
    end

    it "handles CycloneDX packages with no declared license" do
      output = StringIO.new
      allow($stdout).to receive(:puts) { |msg| output.puts(msg) }
      
      described_class.display_license_report(cyclonedx_no_license_sbom)
      report = output.string
      
      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("Total packages: 1")
      expect(report).to include("NOASSERTION: 1 package(s)")
      expect(report).to include("unknown (1.0.0)")
    end

    it "handles empty CycloneDX components" do
      output = StringIO.new
      allow($stdout).to receive(:puts) { |msg| output.puts(msg) }
      
      described_class.display_license_report(cyclonedx_empty_sbom)
      report = output.string
      
      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("Total packages: 0")
    end
  end
end