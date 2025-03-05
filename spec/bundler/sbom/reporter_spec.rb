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
end