require "spec_helper"
require "bundler/cli/sbom"
require "json"

RSpec.describe Bundler::CLI::Sbom do
  let(:cli) { described_class.new }
  
  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      @temp_dir = dir
      Dir.chdir(@temp_dir) do
        example.run
      end
    end
  end

  let(:sample_sbom) do
    {
      "SPDXID" => "SPDXRef-DOCUMENT",
      "packages" => [
        { "name" => "rake", "versionInfo" => "13.0.6", "licenseDeclared" => "MIT" }
      ]
    }
  end

  before(:each) do
    allow(Bundler.ui).to receive(:error)
    allow(Bundler.ui).to receive(:info)
  end

  describe "#dump" do
    before do
      allow(Bundler::Sbom::Generator).to receive(:generate_sbom).and_return(sample_sbom)
    end

    it "generates and writes SBOM to bom.json" do
      cli.dump
      expect(File.exist?("bom.json")).to be true
      
      content = JSON.parse(File.read("bom.json"))
      expect(content).to eq(sample_sbom)
      expect(Bundler.ui).to have_received(:info).with("Generated SBOM at bom.json")
    end

    context "when an error occurs during generation" do
      before do
        allow(Bundler::Sbom::Generator).to receive(:generate_sbom).and_raise(StandardError, "Test error")
      end

      it "handles the error gracefully" do
        expect { cli.dump }.to raise_error(StandardError, "Test error")
      end
    end
  end

  describe "#license" do
    context "when bom.json exists" do
      before do
        File.write("bom.json", JSON.generate(sample_sbom))
        allow(Bundler::Sbom::Generator).to receive(:display_license_report)
      end

      it "calls display_license_report with parsed SBOM" do
        cli.license
        expect(Bundler::Sbom::Generator).to have_received(:display_license_report).with(sample_sbom)
      end
    end

    context "when bom.json does not exist" do
      it "displays error message and exits" do
        expect { cli.license }.to raise_error(SystemExit)
        expect(Bundler.ui).to have_received(:error).with("Error: bom.json not found. Run 'bundle sbom dump' first.")
      end
    end

    context "when bom.json is invalid JSON" do
      before do
        File.write("bom.json", "invalid json")
      end

      it "displays error message and exits" do
        expect { cli.license }.to raise_error(SystemExit)
        expect(Bundler.ui).to have_received(:error).with("Error: bom.json is not a valid JSON file")
      end
    end

    context "when processing valid SBOM with multiple licenses" do
      let(:multi_license_sbom) do
        {
          "packages" => [
            { "name" => "rake", "versionInfo" => "13.0.6", "licenseDeclared" => "MIT" },
            { "name" => "rspec", "versionInfo" => "3.12.0", "licenseDeclared" => "MIT" },
            { "name" => "multi", "versionInfo" => "1.0.0", "licenseDeclared" => "MIT, Apache-2.0" }
          ]
        }
      end

      before do
        File.write("bom.json", JSON.generate(multi_license_sbom))
      end

      it "processes multiple licenses correctly" do
        output = StringIO.new
        $stdout = output
        cli.license
        $stdout = STDOUT

        report = output.string
        expect(report).to include("Total packages: 3")
        expect(report).to include("MIT: 3 package(s)")
        expect(report).to include("Apache-2.0: 1 package(s)")
      end
    end
  end
end