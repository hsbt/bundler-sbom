require "spec_helper"
require "bundler/lockfile_parser"

RSpec.describe Bundler::Sbom::Generator do
  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      @temp_dir = dir
      Dir.chdir(@temp_dir) do
        example.run
      end
    end
  end

  let(:gemfile_content) do
    <<~GEMFILE
      source "https://rubygems.org"
      gem "rake"
    GEMFILE
  end

  let(:lockfile_content) do
    <<~LOCKFILE
      GEM
        remote: https://rubygems.org/
        specs:
          rake (13.0.6)

      PLATFORMS
        ruby

      DEPENDENCIES
        rake
    LOCKFILE
  end

  let(:rake_spec) do
    double(
      "rake_spec",
      name: "rake",
      version: Gem::Version.new("13.0.6"),
      license: "MIT",
      licenses: []
    )
  end

  let(:multi_license_spec) do
    double(
      "multi_license_spec",
      name: "bundler",
      version: Gem::Version.new("2.4.0"),
      license: "",
      licenses: ["MIT", "Apache-2.0"]
    )
  end

  let(:empty_license_spec) do
    double(
      "empty_license_spec",
      name: "no-license",
      version: Gem::Version.new("1.0.0"),
      license: "",
      licenses: []
    )
  end

  let(:nil_license_spec) do
    double(
      "nil_license_spec",
      name: "nil-license",
      version: Gem::Version.new("1.0.0"),
      license: nil,
      licenses: nil
    )
  end

  before(:each) do
    File.write("Gemfile", gemfile_content)
    File.write("Gemfile.lock", lockfile_content)

    # Set up default mocks
    allow(Bundler.default_lockfile).to receive(:exist?).and_return(true)
    allow(Bundler.default_lockfile).to receive(:read).and_return(lockfile_content)
    allow(Gem::Specification).to receive(:find_by_name).and_return(nil)
  end

  describe ".generate_sbom" do
    it "generates SBOM document" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [])
      )

      sbom = described_class.generate_sbom
      expect(sbom["SPDXID"]).to eq("SPDXRef-DOCUMENT")
      expect(sbom["spdxVersion"]).to eq("SPDX-2.2")
      expect(sbom["packages"]).to be_an(Array)
    end

    it "includes package information" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [double(name: "rake", version: Gem::Version.new("13.0.6"))])
      )
      allow(Gem::Specification).to receive(:find_by_name)
        .with("rake", Gem::Version.new("13.0.6"))
        .and_return(rake_spec)

      sbom = described_class.generate_sbom
      package = sbom["packages"].find { |p| p["name"] == "rake" }
      expect(package).not_to be_nil
      expect(package["name"]).to eq("rake")
      expect(package["versionInfo"]).to eq("13.0.6")
      expect(package["licenseDeclared"]).to eq("MIT")
    end

    it "handles multiple licenses from licenses array" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [double(name: "bundler", version: Gem::Version.new("2.4.0"))])
      )
      allow(Gem::Specification).to receive(:find_by_name)
        .with("bundler", Gem::Version.new("2.4.0"))
        .and_return(multi_license_spec)

      sbom = described_class.generate_sbom
      package = sbom["packages"].find { |p| p["name"] == "bundler" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("MIT, Apache-2.0")
    end

    it "sets NOASSERTION for packages with no license information" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [double(name: "no-license", version: Gem::Version.new("1.0.0"))])
      )
      allow(Gem::Specification).to receive(:find_by_name)
        .with("no-license", Gem::Version.new("1.0.0"))
        .and_return(empty_license_spec)

      sbom = described_class.generate_sbom
      package = sbom["packages"].find { |p| p["name"] == "no-license" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end

    it "handles nil license information" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [double(name: "nil-license", version: Gem::Version.new("1.0.0"))])
      )
      allow(Gem::Specification).to receive(:find_by_name)
        .with("nil-license", Gem::Version.new("1.0.0"))
        .and_return(nil_license_spec)

      sbom = described_class.generate_sbom
      package = sbom["packages"].find { |p| p["name"] == "nil-license" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end

    it "handles Gem::LoadError gracefully" do
      allow(Bundler::LockfileParser).to receive(:new).and_return(
        double(specs: [double(name: "missing-gem", version: Gem::Version.new("1.0.0"))])
      )
      allow(Gem::Specification).to receive(:find_by_name)
        .with("missing-gem", anything)
        .and_raise(Gem::LoadError)

      sbom = described_class.generate_sbom
      package = sbom["packages"].find { |p| p["name"] == "missing-gem" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end

    context "when Gemfile.lock does not exist" do
      before do
        FileUtils.rm("Gemfile.lock") if File.exist?("Gemfile.lock")
        mock_lockfile = instance_double(Pathname, exist?: false)
        allow(Bundler).to receive(:default_lockfile).and_return(mock_lockfile)
      end

      it "raises error with message" do
        expect(Bundler.ui).to receive(:error).with("No Gemfile.lock found. Run `bundle install` first.")
        expect { described_class.generate_sbom }.to raise_error(Bundler::Sbom::GemfileLockNotFoundError, "No Gemfile.lock found")
      end
    end
  end
end