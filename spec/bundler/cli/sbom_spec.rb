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
    # デフォルトでbom.xmlとbom.jsonが存在しないと設定
    allow(File).to receive(:exist?).with("bom.json").and_return(false)
    allow(File).to receive(:exist?).with("bom.xml").and_return(false)
  end

  describe "#dump" do
    before do
      allow(Bundler::Sbom::Generator).to receive(:generate_sbom).and_return(sample_sbom)
    end

    context "with default format (json)" do
      it "generates SBOM and saves to file" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom)
        expect(File).to receive(:write).with("bom.json", satisfy { |content| JSON.parse(content) == sample_sbom })
        described_class.start(%w[dump])
      end
    end

    context "with xml format" do
      before do
        allow(Bundler::Sbom::Generator).to receive(:convert_to_xml).and_return("<xml>test</xml>")
      end

      it "generates SBOM in XML format" do
        expect(Bundler::Sbom::Generator).to receive(:generate_sbom)
        expect(Bundler::Sbom::Generator).to receive(:convert_to_xml).with(sample_sbom)
        expect(File).to receive(:write).with("bom.xml", "<xml>test</xml>")
        described_class.start(%w[dump --format xml])
      end
    end

    context "with invalid format" do
      it "shows error message and exits" do
        expect(Bundler.ui).to receive(:error).with("Error: Unsupported format 'invalid'. Supported formats: json, xml")
        expect { described_class.start(%w[dump --format invalid]) }.to raise_error(SystemExit)
      end
    end
  end

  describe "#license" do
    context "when bom.json exists" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(true)
        allow(File).to receive(:exist?).with("bom.xml").and_return(false)
        allow(File).to receive(:read).with("bom.json").and_return(JSON.generate(sample_sbom))
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "calls display_license_report with parsed SBOM" do
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_sbom)
        described_class.start(%w[license])
      end
    end

    context "with xml format" do
      before do
        allow(File).to receive(:exist?).with("bom.xml").and_return(true)
        allow(File).to receive(:read).with("bom.xml").and_return("<xml>test</xml>")
        allow(Bundler::Sbom::Generator).to receive(:parse_xml).and_return(sample_sbom)
        allow(Bundler::Sbom::Reporter).to receive(:display_license_report)
      end

      it "reads XML SBOM and displays license report" do
        expect(Bundler::Sbom::Generator).to receive(:parse_xml).with("<xml>test</xml>")
        expect(Bundler::Sbom::Reporter).to receive(:display_license_report).with(sample_sbom)
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

    context "when bom.json does not exist" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(false)
        allow(File).to receive(:exist?).with("bom.xml").and_return(false)
      end

      it "exits with error message" do
        expect(Bundler.ui).to receive(:error).with("Error: bom.json not found. Run 'bundle sbom dump --format=json' first.")
        expect { described_class.start(%w[license]) }.to raise_error(SystemExit)
      end
    end

    context "when bom.json is invalid JSON" do
      before do
        allow(File).to receive(:exist?).with("bom.json").and_return(true)
        allow(File).to receive(:exist?).with("bom.xml").and_return(false)
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