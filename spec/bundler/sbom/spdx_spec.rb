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

  describe ".generate" do
    it "generates SBOM document" do
      gems = []
      sbom = described_class.generate(gems, "test-project")
      expect(sbom["SPDXID"]).to eq("SPDXRef-DOCUMENT")
      expect(sbom["spdxVersion"]).to eq("SPDX-2.3")
      expect(sbom["packages"]).to be_an(Array)
    end

    it "includes package information" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("rake", Gem::Version.new("13.0.6"))
        .and_return(rake_spec)

      gems = [double(name: "rake", version: Gem::Version.new("13.0.6"))]
      sbom = described_class.generate(gems, "test-project")

      package = sbom["packages"].find { |p| p["name"] == "rake" }
      expect(package).not_to be_nil
      expect(package["name"]).to eq("rake")
      expect(package["versionInfo"]).to eq("13.0.6")
      expect(package["licenseDeclared"]).to eq("MIT")
    end

    it "handles multiple licenses from licenses array" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("bundler", Gem::Version.new("2.4.0"))
        .and_return(multi_license_spec)

      gems = [double(name: "bundler", version: Gem::Version.new("2.4.0"))]
      sbom = described_class.generate(gems, "test-project")

      package = sbom["packages"].find { |p| p["name"] == "bundler" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("MIT, Apache-2.0")
    end

    it "sets NOASSERTION for packages with no license information" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("no-license", Gem::Version.new("1.0.0"))
        .and_return(empty_license_spec)

      gems = [double(name: "no-license", version: Gem::Version.new("1.0.0"))]
      sbom = described_class.generate(gems, "test-project")

      package = sbom["packages"].find { |p| p["name"] == "no-license" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end

    it "handles nil license information" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("nil-license", Gem::Version.new("1.0.0"))
        .and_return(nil_license_spec)

      gems = [double(name: "nil-license", version: Gem::Version.new("1.0.0"))]
      sbom = described_class.generate(gems, "test-project")

      package = sbom["packages"].find { |p| p["name"] == "nil-license" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end

    it "handles Gem::LoadError gracefully" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("missing-gem", anything)
        .and_raise(Gem::LoadError)

      gems = [double(name: "missing-gem", version: Gem::Version.new("1.0.0"))]
      sbom = described_class.generate(gems, "test-project")

      package = sbom["packages"].find { |p| p["name"] == "missing-gem" }
      expect(package).not_to be_nil
      expect(package["licenseDeclared"]).to eq("NOASSERTION")
    end
  end

  describe ".to_xml" do
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

    it "converts SBOM hash to XML format" do
      xml_content = described_class.to_xml(sbom_hash)
      expect(xml_content).to be_a(String)
      expect(xml_content).to include('<?xml version="1.0" encoding="UTF-8"?>')

      # Parse XML to verify structure
      doc = REXML::Document.new(xml_content)
      root = doc.root

      expect(root.name).to eq("SpdxDocument")
      expect(REXML::XPath.first(root, "SPDXID").text).to eq("SPDXRef-DOCUMENT")
      expect(REXML::XPath.first(root, "spdxVersion").text).to eq("SPDX-2.3")
      expect(REXML::XPath.first(root, "name").text).to eq("test-project")

      # Check package information
      package = REXML::XPath.first(root, "package")
      expect(package).not_to be_nil
      expect(REXML::XPath.first(package, "name").text).to eq("rake")
      expect(REXML::XPath.first(package, "versionInfo").text).to eq("13.0.6")
      expect(REXML::XPath.first(package, "licenseDeclared").text).to eq("MIT")

      # Check external reference
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

    it "parses XML content into SBOM hash" do
      doc = REXML::Document.new(xml_content)
      sbom = described_class.parse_xml(doc)

      expect(sbom).to be_a(Hash)
      expect(sbom["SPDXID"]).to eq("SPDXRef-DOCUMENT")
      expect(sbom["spdxVersion"]).to eq("SPDX-2.3")
      expect(sbom["name"]).to eq("test-project")
      expect(sbom["dataLicense"]).to eq("CC0-1.0")

      # Check creation info
      expect(sbom["creationInfo"]).to be_a(Hash)
      expect(sbom["creationInfo"]["created"]).to eq("2023-01-01T12:00:00Z")
      expect(sbom["creationInfo"]["creators"]).to include("Tool: bundle-sbom")

      # Check packages
      expect(sbom["packages"]).to be_an(Array)
      expect(sbom["packages"].size).to eq(1)

      package = sbom["packages"].first
      expect(package["SPDXID"]).to eq("SPDXRef-Package-rake")
      expect(package["name"]).to eq("rake")
      expect(package["versionInfo"]).to eq("13.0.6")
      expect(package["licenseDeclared"]).to eq("MIT")

      # Check external refs
      expect(package["externalRefs"]).to be_an(Array)
      expect(package["externalRefs"].size).to eq(1)

      ext_ref = package["externalRefs"].first
      expect(ext_ref["referenceCategory"]).to eq("PACKAGE_MANAGER")
      expect(ext_ref["referenceType"]).to eq("purl")
      expect(ext_ref["referenceLocator"]).to eq("pkg:gem/rake@13.0.6")
    end
  end
end
