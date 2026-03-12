require "spec_helper"

RSpec.describe Bundler::Sbom::SpecLicenseFinder do
  before(:each) do
    allow(Gem::Specification).to receive(:find_by_name).and_return(nil)
  end

  describe ".find_licenses" do
    context "when spec supports __materialize__" do
      it "uses materialized gemspec for license lookup" do
        materialized_gemspec = double(
          "materialized_gemspec",
          license: "BSD-2-Clause",
          licenses: ["BSD-2-Clause"]
        )
        spec = double(
          "lazy_spec",
          name: "colorize",
          version: Gem::Version.new("1.0.0"),
          __materialize__: materialized_gemspec
        )

        licenses = described_class.find_licenses(spec)
        expect(licenses).to eq(["BSD-2-Clause"])
      end

      it "prefers materialized gemspec over globally installed gem" do
        materialized_gemspec = double(
          "materialized_gemspec",
          license: "BSD-2-Clause",
          licenses: ["BSD-2-Clause"]
        )
        globally_installed_gemspec = double(
          "global_gemspec",
          license: "MIT",
          licenses: ["MIT"]
        )
        spec = double(
          "lazy_spec",
          name: "colorize",
          version: Gem::Version.new("1.0.0"),
          __materialize__: materialized_gemspec
        )

        allow(Gem::Specification).to receive(:find_by_name)
          .with("colorize", Gem::Version.new("1.0.0"))
          .and_return(globally_installed_gemspec)

        licenses = described_class.find_licenses(spec)
        expect(licenses).to eq(["BSD-2-Clause"])
      end

      it "falls back to find_by_name when __materialize__ returns nil" do
        globally_installed_gemspec = double(
          "global_gemspec",
          license: "MIT",
          licenses: ["MIT"]
        )
        spec = double(
          "lazy_spec",
          name: "rake",
          version: Gem::Version.new("13.0.6"),
          __materialize__: nil
        )

        allow(Gem::Specification).to receive(:find_by_name)
          .with("rake", Gem::Version.new("13.0.6"))
          .and_return(globally_installed_gemspec)

        licenses = described_class.find_licenses(spec)
        expect(licenses).to eq(["MIT"])
      end

      it "returns empty array when __materialize__ returns nil and find_by_name raises Gem::LoadError" do
        spec = double(
          "lazy_spec",
          name: "colorize",
          version: Gem::Version.new("1.0.0"),
          __materialize__: nil
        )

        allow(Gem::Specification).to receive(:find_by_name)
          .with("colorize", Gem::Version.new("1.0.0"))
          .and_raise(Gem::LoadError)

        licenses = described_class.find_licenses(spec)
        expect(licenses).to eq([])
      end
    end

    context "when spec does not support __materialize__" do
      it "falls back to Gem::Specification.find_by_name" do
        gemspec = double(
          "gemspec",
          license: "MIT",
          licenses: ["MIT"]
        )
        spec = double(
          "plain_spec",
          name: "rake",
          version: Gem::Version.new("13.0.6")
        )

        allow(Gem::Specification).to receive(:find_by_name)
          .with("rake", Gem::Version.new("13.0.6"))
          .and_return(gemspec)

        licenses = described_class.find_licenses(spec)
        expect(licenses).to eq(["MIT"])
      end
    end
  end
end
