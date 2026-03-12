require "spec_helper"

RSpec.describe Bundler::Sbom::Reporter do
  let(:simple_sbom) do
    Bundler::Sbom::SPDX.new({
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
    })
  end

  let(:empty_sbom) do
    Bundler::Sbom::SPDX.new({
      "packages" => []
    })
  end

  describe "#display_license_report" do
    it "outputs formatted license report" do
      expect { described_class.new(simple_sbom).display_license_report }.to output(/License Usage in SBOM/).to_stdout
    end

    it "handles packages with no declared license" do
      sbom_with_no_license = Bundler::Sbom::SPDX.new({
        "packages" => [
          {
            "name" => "unlicensed-gem",
            "versionInfo" => "1.0.0",
            "licenseDeclared" => "NOASSERTION"
          }
        ]
      })
      expect { described_class.new(sbom_with_no_license).display_license_report }
        .to output(/NOASSERTION: 1 package\(s\)/).to_stdout
    end

    context "when sbom has no packages" do
      it "displays empty report" do
        expect { described_class.new(empty_sbom).display_license_report }
          .to output(/Total packages: 0/).to_stdout
      end
    end
  end

  describe "#display_license_report with CycloneDX format" do
    let(:cyclonedx_sbom) do
      Bundler::Sbom::CycloneDX.new({
        "bomFormat" => "CycloneDX",
        "components" => [
          {
            "name" => "rake",
            "version" => "13.0.6",
            "licenses" => [{"license" => {"id" => "MIT"}}]
          }
        ]
      })
    end

    it "outputs formatted license report from CycloneDX data" do
      expect { described_class.new(cyclonedx_sbom).display_license_report }
        .to output(/License Usage in SBOM/).to_stdout
    end

    it "handles CycloneDX packages with no declared license" do
      no_license_sbom = Bundler::Sbom::CycloneDX.new({
        "bomFormat" => "CycloneDX",
        "components" => [
          {
            "name" => "unlicensed-gem",
            "version" => "1.0.0"
          }
        ]
      })
      expect { described_class.new(no_license_sbom).display_license_report }
        .to output(/NOASSERTION: 1 package\(s\)/).to_stdout
    end

    it "handles empty CycloneDX components" do
      empty_cyclonedx_sbom = Bundler::Sbom::CycloneDX.new({
        "bomFormat" => "CycloneDX",
        "components" => []
      })
      expect { described_class.new(empty_cyclonedx_sbom).display_license_report }
        .to output(/Total packages: 0/).to_stdout
    end
  end
end
