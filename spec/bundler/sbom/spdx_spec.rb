require "spec_helper"
require "bundler/lockfile_parser"
require "rexml/document"

RSpec.describe Bundler::Sbom::SPDX do
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

  before(:each) do
    File.write("Gemfile", gemfile_content)
    File.write("Gemfile.lock", lockfile_content)

    # Set up default mocks
    allow(Bundler.default_lockfile).to receive(:exist?).and_return(true)
    allow(Bundler.default_lockfile).to receive(:read).and_return(lockfile_content)
  end

  describe ".generate" do
    it "generates SBOM instance" do
      sbom = described_class.generate([], "test-project")
      expect(sbom).to be_a(described_class)
      expect(sbom.to_hash["SPDXID"]).to eq("SPDXRef-DOCUMENT")
      expect(sbom.to_hash["spdxVersion"]).to eq("SPDX-2.3")
      expect(sbom.to_hash["packages"]).to be_an(Array)
    end

    it "includes package information" do
      gem_data = [{name: "rake", version: "13.0.6", licenses: ["MIT"]}]
      sbom = described_class.generate(gem_data, "test-project")

      package = sbom.to_hash["packages"].find { |p| p["name"] == "rake" }
      expect(package).not_to be_nil
      expect(package["name"]).to eq("rake")
      expect(package["versionInfo"]).to eq("13.0.6")
      expect(package["licenseDeclared"]).to eq("MIT")
    end

    it "handles multiple licenses from licenses array" do
      gem_data = [{name: "bundler", version: "2.4.0", licenses: ["MIT", "Apache-2.0"]}]
      sbom = described_class.generate(gem_data, "test-project")

      package = sbom.to_hash["packages"].find { |p| p["name"] == "bundler" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("MIT AND Apache-2.0")
    end

    it "sets NOASSERTION for packages with no license information" do
      gem_data = [{name: "no-license", version: "1.0.0", licenses: []}]
      sbom = described_class.generate(gem_data, "test-project")

      package = sbom.to_hash["packages"].find { |p| p["name"] == "no-license" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end
  end

  describe "#to_xml" do
    let(:sbom_hash) do
      {
        "SPDXID" => "SPDXRef-DOCUMENT",
        "spdxVersion" => "SPDX-2.3",
        "name" => "test-project",
        "dataLicense" => "CC0-1.0",
        "documentNamespace" => "https://spdx.org/spdxdocs/test-project-123",
        "creationInfo" => {
          "created" => "2023-01-01T12:00:00Z",
          "creators" => ["Tool: bundle-sbom"],
          "licenseListVersion" => "3.20"
        },
        "documentDescribes" => ["SPDXRef-Package-rake"],
        "packages" => [
          {
            "SPDXID" => "SPDXRef-Package-rake",
            "name" => "rake",
            "versionInfo" => "13.0.6",
            "downloadLocation" => "NOASSERTION",
            "filesAnalyzed" => false,
            "licenseConcluded" => "MIT",
            "licenseDeclared" => "MIT",
            "copyrightText" => "NOASSERTION",
            "supplier" => "NOASSERTION",
            "externalRefs" => [
              {
                "referenceCategory" => "PACKAGE_MANAGER",
                "referenceType" => "purl",
                "referenceLocator" => "pkg:gem/rake@13.0.6"
              }
            ]
          }
        ]
      }
    end

    it "converts SBOM instance to XML format" do
      sbom = described_class.new(sbom_hash)
      xml_content = sbom.to_xml
      expect(xml_content).to be_a(String)
      expect(xml_content).to include('<?xml version="1.0" encoding="UTF-8"?>')

      doc = REXML::Document.new(xml_content)
      root = doc.root

      expect(root.name).to eq("SpdxDocument")
      expect(REXML::XPath.first(root, "SPDXID").text).to eq("SPDXRef-DOCUMENT")
      expect(REXML::XPath.first(root, "spdxVersion").text).to eq("SPDX-2.3")
      expect(REXML::XPath.first(root, "name").text).to eq("test-project")

      package = REXML::XPath.first(root, "package")
      expect(package).not_to be_nil
      expect(REXML::XPath.first(package, "name").text).to eq("rake")
      expect(REXML::XPath.first(package, "versionInfo").text).to eq("13.0.6")
      expect(REXML::XPath.first(package, "licenseDeclared").text).to eq("MIT")

      ext_ref = REXML::XPath.first(package, "externalRef")
      expect(ext_ref).not_to be_nil
      expect(REXML::XPath.first(ext_ref, "referenceLocator").text).to eq("pkg:gem/rake@13.0.6")
    end
  end

  describe ".parse_xml" do
    let(:xml_content) do
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <SpdxDocument xmlns="https://spdx.org/spdxdocs/">
          <SPDXID>SPDXRef-DOCUMENT</SPDXID>
          <spdxVersion>SPDX-2.3</spdxVersion>
          <name>test-project</name>
          <dataLicense>CC0-1.0</dataLicense>
          <documentNamespace>https://spdx.org/spdxdocs/test-project-123</documentNamespace>
          <creationInfo>
            <created>2023-01-01T12:00:00Z</created>
            <creator>Tool: bundle-sbom</creator>
            <licenseListVersion>3.20</licenseListVersion>
          </creationInfo>
          <documentDescribes>SPDXRef-Package-rake</documentDescribes>
          <package>
            <SPDXID>SPDXRef-Package-rake</SPDXID>
            <name>rake</name>
            <versionInfo>13.0.6</versionInfo>
            <downloadLocation>NOASSERTION</downloadLocation>
            <filesAnalyzed>false</filesAnalyzed>
            <licenseConcluded>MIT</licenseConcluded>
            <licenseDeclared>MIT</licenseDeclared>
            <copyrightText>NOASSERTION</copyrightText>
            <supplier>NOASSERTION</supplier>
            <externalRef>
              <referenceCategory>PACKAGE_MANAGER</referenceCategory>
              <referenceType>purl</referenceType>
              <referenceLocator>pkg:gem/rake@13.0.6</referenceLocator>
            </externalRef>
          </package>
        </SpdxDocument>
      XML
    end

    it "parses XML content into SBOM instance" do
      doc = REXML::Document.new(xml_content)
      sbom = described_class.parse_xml(doc)

      expect(sbom).to be_a(described_class)
      expect(sbom.to_hash["SPDXID"]).to eq("SPDXRef-DOCUMENT")
      expect(sbom.to_hash["spdxVersion"]).to eq("SPDX-2.3")
      expect(sbom.to_hash["name"]).to eq("test-project")
      expect(sbom.to_hash["dataLicense"]).to eq("CC0-1.0")

      expect(sbom.to_hash["creationInfo"]).to be_a(Hash)
      expect(sbom.to_hash["creationInfo"]["created"]).to eq("2023-01-01T12:00:00Z")
      expect(sbom.to_hash["creationInfo"]["creators"]).to include("Tool: bundle-sbom")

      expect(sbom.to_hash["packages"]).to be_an(Array)
      expect(sbom.to_hash["packages"].size).to eq(1)

      package = sbom.to_hash["packages"].first
      expect(package["SPDXID"]).to eq("SPDXRef-Package-rake")
      expect(package["name"]).to eq("rake")
      expect(package["versionInfo"]).to eq("13.0.6")
      expect(package["licenseDeclared"]).to eq("MIT")

      expect(package["externalRefs"]).to be_an(Array)
      expect(package["externalRefs"].size).to eq(1)

      ext_ref = package["externalRefs"].first
      expect(ext_ref["referenceCategory"]).to eq("PACKAGE_MANAGER")
      expect(ext_ref["referenceType"]).to eq("purl")
      expect(ext_ref["referenceLocator"]).to eq("pkg:gem/rake@13.0.6")
    end
  end
end
