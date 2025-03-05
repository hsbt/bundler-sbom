require "spec_helper"
require "tempfile"
require "fileutils"

RSpec.describe Bundler::Sbom::Generator do
  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      @temp_dir = dir
      Dir.chdir(@temp_dir) do
        example.run
      end
    end
  end

  let(:gemfile_lock_content) do
    <<~LOCKFILE
      GEM
        remote: https://rubygems.org/
        specs:
          rake (13.0.6)
          rspec (3.12.0)
            rspec-core (~> 3.12.0)
            rspec-expectations (~> 3.12.0)
            rspec-mocks (~> 3.12.0)
          multi-license (1.0.0)
          empty-license (0.1.0)
          nil-license (0.2.0)

      PLATFORMS
        ruby

      DEPENDENCIES
        rake
        rspec (~> 3.12)
        multi-license
        empty-license
        nil-license

      BUNDLED WITH
         2.4.10
    LOCKFILE
  end

  before(:each) do
    allow(Bundler).to receive(:default_lockfile).and_return(@temp_dir.join("Gemfile.lock"))
    File.write(@temp_dir.join("Gemfile.lock"), gemfile_lock_content)
    allow(SecureRandom).to receive(:uuid).and_return("test-uuid")
    allow(Time).to receive_message_chain(:now, :utc, :strftime).and_return("2023-01-01T00:00:00Z")

    # Default mock for all gem specs
    allow(Gem::Specification).to receive(:find_by_name) do |name, version|
      case name
      when "rake"
        double(license: "MIT", licenses: [])
      when "rspec"
        double(license: nil, licenses: ["MIT"])
      when "multi-license"
        double(license: "MIT", licenses: ["Apache-2.0", "BSD-3-Clause"])
      when "empty-license"
        double(license: "", licenses: [])
      when "nil-license"
        double(license: nil, licenses: nil)
      else
        raise Gem::LoadError, "Could not find #{name} (#{version})"
      end
    end
  end

  describe ".generate_sbom" do
    subject(:sbom) { described_class.generate_sbom }

    context "when Gemfile.lock exists" do
      it "generates valid SPDX SBOM" do
        expect(sbom).to be_a(Hash)
        expect(sbom["SPDXID"]).to eq("SPDXRef-DOCUMENT")
        expect(sbom["spdxVersion"]).to eq("SPDX-2.2")
        expect(sbom["name"]).to eq(File.basename(Dir.pwd))
        expect(sbom["documentNamespace"]).to eq("https://spdx.org/spdxdocs/#{File.basename(Dir.pwd)}-test-uuid")
      end

      it "includes creation info" do
        expect(sbom["creationInfo"]).to include(
          "created" => "2023-01-01T00:00:00Z",
          "creators" => ["Tool: bundle-sbom"],
          "licenseListVersion" => "3.17"
        )
      end

      it "includes packages from Gemfile.lock" do
        packages = sbom["packages"]
        expect(packages).to be_an(Array)
        expect(packages).not_to be_empty

        rake_package = packages.find { |p| p["name"] == "rake" }
        expect(rake_package).to include(
          "SPDXID" => "SPDXRef-Package-rake",
          "versionInfo" => "13.0.6",
          "downloadLocation" => "NOASSERTION",
          "licenseDeclared" => "MIT"
        )

        rspec_package = packages.find { |p| p["name"] == "rspec" }
        expect(rspec_package).to include(
          "SPDXID" => "SPDXRef-Package-rspec",
          "versionInfo" => "3.12.0",
          "downloadLocation" => "NOASSERTION",
          "licenseDeclared" => "MIT"
        )
      end

      it "combines all unique licenses" do
        packages = sbom["packages"]
        multi_package = packages.find { |p| p["name"] == "multi-license" }
        expect(multi_package["licenseDeclared"]).to eq("MIT, Apache-2.0, BSD-3-Clause")
      end

      it "handles empty license strings" do
        packages = sbom["packages"]
        empty_package = packages.find { |p| p["name"] == "empty-license" }
        expect(empty_package["licenseDeclared"]).to eq("NOASSERTION")
      end

      it "handles nil licenses" do
        packages = sbom["packages"]
        nil_package = packages.find { |p| p["name"] == "nil-license" }
        expect(nil_package["licenseDeclared"]). to eq("NOASSERTION")
      end

      # SPDX 2.2 Specification Compliance Tests
      it "contains all required SPDX 2.2 fields" do
        expect(sbom).to include(
          "SPDXID",
          "spdxVersion",
          "creationInfo",
          "name",
          "dataLicense",
          "documentNamespace"
        )
      end

      it "has valid SPDX data license" do
        expect(sbom["dataLicense"]).to eq("CC0-1.0")
      end

      it "has valid document namespace format" do
        expect(sbom["documentNamespace"]).to match(%r{^https://spdx\.org/spdxdocs/[^/]+(?:-[a-f0-9-]+)?$})
      end

      context "package information compliance" do
        let(:package) { sbom["packages"].first }

        it "contains required package fields" do
          expect(package).to include(
            "SPDXID",
            "name",
            "versionInfo",
            "downloadLocation",
            "filesAnalyzed",
            "licenseConcluded",
            "licenseDeclared"
          )
        end

        it "has valid package SPDXID format" do
          expect(package["SPDXID"]).to match(/^SPDXRef-Package-[A-Za-z0-9.-]+$/)
        end

        it "has valid external references" do
          expect(package["externalRefs"]).to be_an(Array)
          external_ref = package["externalRefs"].first
          expect(external_ref).to include(
            "referenceCategory" => "PACKAGE_MANAGER",
            "referenceType" => "purl",
            "referenceLocator" => match(%r{^pkg:gem/[^@]+@\d+\.\d+\.\d+$})
          )
        end

        it "has correct filesAnalyzed value" do
          expect(package["filesAnalyzed"]).to be false
        end
      end
    end

    context "when Gemfile.lock does not exist" do
      before do
        FileUtils.rm_f(@temp_dir.join("Gemfile.lock"))
      end

      it "raises an error" do
        expect { sbom }.to raise_error(SystemExit)
      end
    end
  end

  describe ".analyze_licenses" do
    let(:sample_sbom) do
      {
        "packages" => [
          { "name" => "rake", "licenseDeclared" => "MIT" },
          { "name" => "rspec", "licenseDeclared" => "MIT" },
          { "name" => "multi-license", "licenseDeclared" => "MIT, Apache-2.0" },
          { "name" => "no-license", "licenseDeclared" => "NOASSERTION" },
          { "name" => "complex", "licenseDeclared" => "MIT, Apache-2.0, BSD-3-Clause" }
        ]
      }
    end

    it "correctly counts license occurrences" do
      license_count = described_class.analyze_licenses(sample_sbom)
      expect(license_count["MIT"]).to eq(4)
      expect(license_count["Apache-2.0"]).to eq(2)
      expect(license_count["BSD-3-Clause"]).to eq(1)
      expect(license_count["NOASSERTION"]).to eq(1)
    end

    context "when sbom has no packages" do
      let(:empty_sbom) { { "packages" => [] } }

      it "returns empty hash" do
        expect(described_class.analyze_licenses(empty_sbom)).to be_empty
      end
    end
  end

  describe ".display_license_report" do
    let(:sample_sbom) do
      {
        "packages" => [
          { "name" => "rake", "versionInfo" => "13.0.6", "licenseDeclared" => "MIT" },
          { "name" => "rspec", "versionInfo" => "3.12.0", "licenseDeclared" => "MIT" },
          { "name" => "multi-license", "versionInfo" => "1.0.0", "licenseDeclared" => "MIT, Apache-2.0" },
          { "name" => "no-license", "versionInfo" => "0.1.0", "licenseDeclared" => "NOASSERTION" },
          { "name" => "complex", "versionInfo" => "2.0.0", "licenseDeclared" => "MIT, Apache-2.0, BSD-3-Clause" }
        ]
      }
    end

    it "outputs formatted license report" do
      output = StringIO.new
      $stdout = output
      described_class.display_license_report(sample_sbom)
      $stdout = STDOUT

      report = output.string
      expect(report).to include("=== License Usage in SBOM ===")
      expect(report).to include("Total packages: 5")
      expect(report).to include("MIT: 4 package(s)")
      expect(report).to include("Apache-2.0: 2 package(s)")
      expect(report).to include("BSD-3-Clause: 1 package(s)")
      expect(report).to include("NOASSERTION: 1 package(s)")
      expect(report).to match(/rake \(13\.0\.6\)/)
      expect(report).to match(/rspec \(3\.12\.0\)/)
      expect(report).to match(/multi-license \(1\.0\.0\)/)
      expect(report).to match(/no-license \(0\.1\.0\)/)
      expect(report).to match(/complex \(2\.0\.0\)/)
    end

    context "when sbom has no packages" do
      let(:empty_sbom) { { "packages" => [] } }

      it "displays empty report" do
        output = StringIO.new
        $stdout = output
        described_class.display_license_report(empty_sbom)
        $stdout = STDOUT

        report = output.string
        expect(report).to include("Total packages: 0")
      end
    end
  end
end