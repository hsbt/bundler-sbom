require "spec_helper"
require "json"
require "fileutils"

RSpec.describe Bundler::Sbom::CLI do
  let(:cli) { described_class.new }

  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      @temp_dir = dir
      Dir.chdir(@temp_dir) do
        example.run
      end
    end
  end

  let(:sample_spdx_sbom) do
    {
      "SPDXID" => "SPDXRef-DOCUMENT",
      "packages" => [
        { "name" => "rake", "versionInfo" => "13.0.6", "licenseDeclared" => "MIT" }
      ]
    }
  end

  let(:sample_cyclonedx_sbom) do
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version" => 1,
      "components" => [
        { "name" => "rake", "version" => "13.0.6", "type" => "library" }
      ]
    }
  end

  before(:each) do
    allow(Bundler.ui).to receive(:error)
    allow(Bundler.ui).to receive(:info)
    # Default setting: no SBOM files exist
    allow(File).to receive(:exist?).with("bom.json").and_return(false)
    allow(File).to receive(:exist?).with("bom.xml").and_return(false)
    allow(File).to receive(:exist?).with("bom-cyclonedx.json").and_return(false)
    allow(File).to receive(:exist?).with("bom-cyclonedx.xml").and_return(false)
  end

  describe "#dump" do
    before do
      allow(Bundler::Sbom::Generator).to receive(:generate_sbom).and_return(sample_spdx_sbom)
      allow(Bundler::Sbom::Generator).to receive(:generate_sbom).with("cyclonedx").and_return(sample_cyclonedx_sbom)
    end

    context "with default format (json) and default SBOM format (spdx)" do
      it "generates SPDX SBOM and saves to bom.json file" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom).with("spdx")
        expect(File).to receive(:write).with("bom.json", satisfy { |content| JSON.parse(content) == sample_spdx_sbom })
        expect(Bundler.ui).to receive(:info).with("Generated SPDX SBOM at bom.json")
        described_class.start(%w[dump])
      end
    end

    context "with xml format and default SBOM format (spdx)" do
      before do
        allow(Bundler::Sbom::Generator).to receive(:convert_to_xml).with(sample_spdx_sbom).and_return("<xml>spdx</xml>")
      end

      it "generates SPDX SBOM in XML format" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom).with("spdx")
        expect(Bundler::Sbom::Generator).to receive(:convert_to_xml).with(sample_spdx_sbom)
        expect(File).to receive(:write).with("bom.xml", "<xml>spdx</xml>")
        expect(Bundler.ui).to receive(:info).with("Generated SPDX SBOM at bom.xml")
        described_class.start(%w[dump --format xml])
      end
    end

    context "with json format and cyclonedx SBOM format" do
      it "generates CycloneDX SBOM and saves to bom-cyclonedx.json file" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom).with("cyclonedx")
        expect(File).to receive(:write).with("bom-cyclonedx.json", satisfy { |content|
 JSON.parse(content) == sample_cyclonedx_sbom })
        expect(Bundler.ui).to receive(:info).with("Generated CYCLONEDX SBOM at bom-cyclonedx.json")
        described_class.start(%w[dump --sbom cyclonedx])
      end
    end

    context "with xml format and cyclonedx SBOM format" do
      before do
        allow(Bundler::Sbom::Generator).to receive(:convert_to_xml).with(sample_cyclonedx_sbom).and_return("<xml>cyclonedx</xml>")
      end

      it "generates CycloneDX SBOM in XML format" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom).with("cyclonedx")
        expect(Bundler::Sbom::Generator).to receive(:convert_to_xml).with(sample_cyclonedx_sbom)
        expect(File).to receive(:write).with("bom-cyclonedx.xml", "<xml>cyclonedx</xml>")
        expect(Bundler.ui).to receive(:info).with("Generated CYCLONEDX SBOM at bom-cyclonedx.xml")
        described_class.start(%w[dump --format xml --sbom cyclonedx])
      end
    end

    context "with invalid output format" do
      it "shows error message and exits" do
        expect(Bundler.ui).to receive(:error).with("Error: Unsupported output format 'invalid'. Supported formats: json, xml")
        expect { described_class.start(%w[dump --format invalid]) }.to raise_error(SystemExit)
      end
    end

    context "with invalid SBOM format" do
      it "shows error message and exits" do
        expect(Bundler.ui).to receive(:error).with("Error: Unsupported SBOM format 'invalid'. Supported formats: spdx, cyclonedx")
        expect { described_class.start(%w[dump --sbom invalid]) }.to raise_error(SystemExit)
      end
    end
  end

  describe "#license" do
    context "when bom.json exists" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(true)
        allow(File).to receive(:read).with("bom.json").and_return(JSON.generate(sample_spdx_sbom))
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "calls display_license_report with parsed SBOM" do
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_spdx_sbom)
        described_class.start(%w[license])
      end
    end

    context "when bom-cyclonedx.json exists but bom.json doesn't" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(false)
        allow(File).to receive(:exist?).with("bom-cyclonedx.json").and_return(true)
        allow(File).to receive(:read).with("bom-cyclonedx.json").and_return(JSON.generate(sample_cyclonedx_sbom))
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "reads CycloneDX JSON SBOM and displays license report" do
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_cyclonedx_sbom)
        described_class.start(%w[license])
      end
    end

    context "when bom-cyclonedx.xml exists but bom.json doesn't" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(false)
        allow(File).to receive(:exist?).with("bom.xml").and_return(false)
        allow(File).to receive(:exist?).with("bom-cyclonedx.json").and_return(false)
        allow(File).to receive(:exist?).with("bom-cyclonedx.xml").and_return(true)
        allow(File).to receive(:read).with("bom-cyclonedx.xml").and_return("<xml>cyclonedx</xml>")
        allow(Bundler::Sbom::Generator).to receive(:parse_xml).and_return(sample_cyclonedx_sbom)
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "reads CycloneDX XML SBOM and displays license report" do
        expect(Bundler::Sbom::Generator).to receive(:parse_xml).with("<xml>cyclonedx</xml>")
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_cyclonedx_sbom)
        described_class.start(%w[license])
      end
    end

    context "with xml format" do
      before do
        allow(File).to receive(:exist?).with("bom.xml").and_return(true)
        allow(File).to receive(:read).with("bom.xml").and_return("<xml>spdx</xml>")
        allow(Bundler::Sbom::Generator).to receive(:parse_xml).and_return(sample_spdx_sbom)
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "reads XML SBOM and displays license report" do
        expect(Bundler::Sbom::Generator).to receive(:parse_xml).with("<xml>spdx</xml>")
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_spdx_sbom)
        described_class.start(%w[license --format xml])
      end

      context "when XML is invalid" do
        before do
          allow(Bundler::Sbom::Generator).to receive(:parse_xml).and_raise(StandardError.new("Invalid XML"))
        end

        it "shows error message and exits" do
          expect(Bundler.ui).to receive(:error).with("Error processing bom.xml: Invalid XML")
          expect { described_class.start(%w[license --format xml]) }.to raise_error(SystemExit)
        end
      end
    end

    context "with specific file path" do
      before do
        allow(File).to receive(:exist?).with("custom-bom.json").and_return(true)
        allow(File).to receive(:read).with("custom-bom.json").and_return(JSON.generate(sample_cyclonedx_sbom))
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "reads from the specified file" do
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_cyclonedx_sbom)
        described_class.start(%w[license --file custom-bom.json])
      end
    end

    context "when no SBOM files exist" do
      before do
        allow(File).to receive(:exist?).with(anything).and_return(false)
      end

      it "exits with error message" do
        expect(Bundler.ui).to receive(:error).with("Error: bom.json not found. Run 'bundle sbom dump --format=json --sbom=spdx' first.")
        expect { described_class.start(%w[license]) }.to raise_error(SystemExit)
      end
    end

    context "when bom.json is invalid JSON" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(true)
        allow(File).to receive(:read).with("bom.json").and_return("invalid json content")
      end

      it "shows an error message and exits" do
        expect(Bundler.ui).to receive(:error).with("Error: bom.json is not a valid JSON file")
        expect { described_class.start(%w[license]) }.to raise_error(SystemExit)
      end
    end

    context "with invalid format" do
      it "shows error message and exits" do
        expect(Bundler.ui).to receive(:error).with("Error: Unsupported format 'invalid'. Supported formats: json, xml")
        expect { described_class.start(%w[license --format invalid]) }.to raise_error(SystemExit)
      end
    end
  end
end
