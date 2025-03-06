require "spec_helper"

RSpec.describe Bundler::Sbom::Reporter do
  let(:simple_sbom) do
    {
      "packages" => [
        {
          "name" => "rake",
          "versionInfo" => "13.0.6",
          "licenseDeclared" => "MIT"
        },
        {
          "name" => "bundler",
          "versionInfo" => "2.4.0",
          "licenseDeclared" => "MIT, Apache-2.0"
        }
      ]
    }
  end

  let(:empty_sbom) do
    {
      "packages" => []
    }
  end

  describe ".analyze_licenses" do
    it "correctly counts license occurrences" do
      result = described_class.analyze_licenses(simple_sbom)
      expect(result["MIT"]).to eq(2)
      expect(result["Apache-2.0"]).to eq(1)
    end

    it "handles packages with no license" do
      sbom_with_no_license = {
        "packages" => [
          {
            "name" => "rake",
            "versionInfo" => "13.0.6",
            "licenseDeclared" => "NOASSERTION"
          }
        ]
      }
      result = described_class.analyze_licenses(sbom_with_no_license)
      expect(result["NOASSERTION"]).to eq(1)
    end

    context "when sbom has no packages" do
      it "returns empty hash" do
        result = described_class.analyze_licenses(empty_sbom)
        expect(result).to be_empty
      end
    end
  end

  describe ".display_license_report" do
    it "outputs formatted license report" do
      expect { described_class.display_license_report(simple_sbom) }.to output(/License Usage in SBOM/).to_stdout
    end

    it "handles packages with no declared license" do
      sbom_with_no_license = {
        "packages" => [
          {
            "name" => "unlicensed-gem",
            "versionInfo" => "1.0.0",
            "licenseDeclared" => "NOASSERTION"
          }
        ]
      }
      expect { described_class.display_license_report(sbom_with_no_license) }
        .to output(/NOASSERTION: 1 package\(s\)/).to_stdout
    end

    context "when sbom has no packages" do
      it "displays empty report" do
        expect { described_class.display_license_report(empty_sbom) }
          .to output(/Total packages: 0/).to_stdout
      end
    end
  end

  describe ".sbom_format" do
    it "correctly detects CycloneDX format" do
      cyclonedx_sbom = { "bomFormat" => "CycloneDX" }
      expect(described_class.sbom_format(cyclonedx_sbom)).to eq(:cyclonedx)
    end

    it "defaults to SPDX format" do
      spdx_sbom = { "SPDXID" => "SPDXRef-DOCUMENT" }
      expect(described_class.sbom_format(spdx_sbom)).to eq(:spdx)
    end
  end

  describe ".display_license_report with CycloneDX format" do
    let(:cyclonedx_sbom) do
      {
        "bomFormat" => "CycloneDX",
        "components" => [
          {
            "name" => "rake",
            "version" => "13.0.6",
            "licenses" => [{ "license" => { "id" => "MIT" } }]
          }
        ]
      }
    end

    it "outputs formatted license report from CycloneDX data" do
      expect { described_class.display_license_report(cyclonedx_sbom) }
        .to output(/License Usage in SBOM/).to_stdout
    end

    it "handles CycloneDX packages with no declared license" do
      no_license_sbom = {
        "bomFormat" => "CycloneDX",
        "components" => [
          {
            "name" => "unlicensed-gem",
            "version" => "1.0.0"
          }
        ]
      }
      expect { described_class.display_license_report(no_license_sbom) }
        .to output(/NOASSERTION: 1 package\(s\)/).to_stdout
    end

    it "handles empty CycloneDX components" do
      empty_cyclonedx_sbom = {
        "bomFormat" => "CycloneDX",
        "components" => []
      }
      expect { described_class.display_license_report(empty_cyclonedx_sbom) }
        .to output(/Total packages: 0/).to_stdout
    end
  end
end