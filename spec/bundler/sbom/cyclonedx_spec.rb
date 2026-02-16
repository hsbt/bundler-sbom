require "spec_helper"
require "bundler/lockfile_parser"
require "rexml/document"

RSpec.describe Bundler::Sbom::CycloneDX do
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
    it "generates CycloneDX SBOM document" do
      gems = []
      sbom = described_class.generate(gems, "test-project")
      expect(sbom["bomFormat"]).to eq("CycloneDX")
      expect(sbom["specVersion"]).to eq("1.4")
      expect(sbom["serialNumber"]).to match(/^urn:uuid:[0-9a-f-]+$/)
      expect(sbom["components"]).to be_an(Array)
    end

    it "includes component information" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("rake", Gem::Version.new("13.0.6"))
        .and_return(rake_spec)

      gems = [double(name: "rake", version: Gem::Version.new("13.0.6"))]
      sbom = described_class.generate(gems, "test-project")

      component = sbom["components"].find { |c| c["name"] == "rake" }
      expect(component).not_to be_nil
      expect(component["name"]).to eq("rake")
      expect(component["version"]).to eq("13.0.6")
      expect(component["type"]).to eq("library")
      expect(component["purl"]).to eq("pkg:gem/rake@13.0.6")
      expect(component["licenses"]).to be_an(Array)
      expect(component["licenses"].first["license"]["id"]).to eq("MIT")
    end

    it "handles multiple licenses" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("bundler", Gem::Version.new("2.4.0"))
        .and_return(multi_license_spec)

      gems = [double(name: "bundler", version: Gem::Version.new("2.4.0"))]
      sbom = described_class.generate(gems, "test-project")

      component = sbom["components"].find { |c| c["name"] == "bundler" }
      expect(component).not_to be_nil
      expect(component["licenses"].size).to eq(2)
      license_ids = component["licenses"].map { |l| l["license"]["id"] }
      expect(license_ids).to include("MIT")
      expect(license_ids).to include("Apache-2.0")
    end

    it "omits licenses array for packages with no license information" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("no-license", Gem::Version.new("1.0.0"))
        .and_return(empty_license_spec)

      gems = [double(name: "no-license", version: Gem::Version.new("1.0.0"))]
      sbom = described_class.generate(gems, "test-project")

      component = sbom["components"].find { |c| c["name"] == "no-license" }
      expect(component).not_to be_nil
      expect(component["licenses"]).to be_nil
    end

    it "handles Gem::LoadError gracefully" do
      allow(Gem::Specification).to receive(:find_by_name)
        .with("missing-gem", anything)
        .and_raise(Gem::LoadError)

      gems = [double(name: "missing-gem", version: Gem::Version.new("1.0.0"))]
      sbom = described_class.generate(gems, "test-project")

      component = sbom["components"].find { |c| c["name"] == "missing-gem" }
      expect(component).not_to be_nil
      expect(component["licenses"]).to be_nil
    end

    it "includes metadata with timestamp and tools" do
      gems = []
      sbom = described_class.generate(gems, "test-project")

      expect(sbom["metadata"]).to be_a(Hash)
      expect(sbom["metadata"]["timestamp"]).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
      expect(sbom["metadata"]["tools"]).to be_an(Array)
      expect(sbom["metadata"]["tools"].first["name"]).to eq("bundle-sbom")
    end
  end

  describe ".to_xml" do
    let(:cyclonedx_hash) do
      {
        "bomFormat" => "CycloneDX",
        "specVersion" => "1.4",
        "serialNumber" => "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version" => 1,
        "metadata" => {
          "timestamp" => "2023-01-01T12:00:00Z",
          "tools" => [
            {
              "vendor" => "Bundler",
              "name" => "bundle-sbom",
              "version" => "0.1.0"
            }
          ],
          "component" => {
            "type" => "application",
            "name" => "test-project",
            "version" => "0.0.0"
          }
        },
        "components" => [
          {
            "type" => "library",
            "name" => "rake",
            "version" => "13.0.6",
            "purl" => "pkg:gem/rake@13.0.6",
            "licenses" => [
              {
                "license" => {
                  "id" => "MIT"
                }
              }
            ]
          },
          {
            "type" => "library",
            "name" => "bundler",
            "version" => "2.4.0",
            "purl" => "pkg:gem/bundler@2.4.0",
            "licenses" => [
              {
                "license" => {
                  "id" => "MIT"
                }
              },
              {
                "license" => {
                  "id" => "Apache-2.0"
                }
              }
            ]
          }
        ]
      }
    end

    it "converts CycloneDX SBOM hash to XML format" do
      xml_content = described_class.to_xml(cyclonedx_hash)
      expect(xml_content).to be_a(String)
      expect(xml_content).to include('<?xml version="1.0" encoding="UTF-8"?>')

      # Parse XML to verify structure
      doc = REXML::Document.new(xml_content)
      root = doc.root

      expect(root.name).to eq("bom")
      expect(root.namespace).to include("cyclonedx.org/schema")
      expect(root.attributes["serialNumber"]).to eq("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")

      # Check metadata
      metadata = REXML::XPath.first(root, "metadata")
      expect(metadata).not_to be_nil
      expect(REXML::XPath.first(metadata, "timestamp").text).to eq("2023-01-01T12:00:00Z")

      # Check tools
      tools = REXML::XPath.first(metadata, "tools")
      expect(tools).not_to be_nil
      tool = REXML::XPath.first(tools, "tool")
      expect(tool).not_to be_nil
      expect(REXML::XPath.first(tool, "name").text).to eq("bundle-sbom")

      # Check components
      components = REXML::XPath.first(root, "components")
      expect(components).not_to be_nil
      comps = REXML::XPath.each(components, "component").to_a
      expect(comps.size).to eq(2)

      # Check first component
      comp1 = comps[0]
      expect(comp1.attributes["type"]).to eq("library")
      expect(REXML::XPath.first(comp1, "name").text).to eq("rake")
      expect(REXML::XPath.first(comp1, "version").text).to eq("13.0.6")
      expect(REXML::XPath.first(comp1, "purl").text).to eq("pkg:gem/rake@13.0.6")

      # Check license in first component
      licenses1 = REXML::XPath.first(comp1, "licenses")
      expect(licenses1).not_to be_nil
      license1 = REXML::XPath.first(licenses1, "license")
      expect(license1).not_to be_nil
      expect(REXML::XPath.first(license1, "id").text).to eq("MIT")

      # Check second component with multiple licenses
      comp2 = comps[1]
      expect(comp2.attributes["type"]).to eq("library")
      expect(REXML::XPath.first(comp2, "name").text).to eq("bundler")

      # Check licenses in second component
      licenses2 = REXML::XPath.first(comp2, "licenses")
      expect(licenses2).not_to be_nil
      license_nodes = REXML::XPath.each(licenses2, "license").to_a
      expect(license_nodes.size).to eq(2)
      license_ids = license_nodes.map { |node| REXML::XPath.first(node, "id").text }
      expect(license_ids).to include("MIT")
      expect(license_ids).to include("Apache-2.0")
    end
  end

  describe ".parse_xml" do
    let(:cyclonedx_xml_content) do
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1">
          <metadata>
            <timestamp>2023-01-01T12:00:00Z</timestamp>
            <tools>
              <tool>
                <vendor>Bundler</vendor>
                <name>bundle-sbom</name>
                <version>0.1.0</version>
              </tool>
            </tools>
            <component type="application">
              <name>test-project</name>
              <version>0.0.0</version>
            </component>
          </metadata>
          <components>
            <component type="library">
              <name>rake</name>
              <version>13.0.6</version>
              <purl>pkg:gem/rake@13.0.6</purl>
              <licenses>
                <license>
                  <id>MIT</id>
                </license>
              </licenses>
            </component>
            <component type="library">
              <name>bundler</name>
              <version>2.4.0</version>
              <purl>pkg:gem/bundler@2.4.0</purl>
              <licenses>
                <license>
                  <id>MIT</id>
                </license>
                <license>
                  <id>Apache-2.0</id>
                </license>
              </licenses>
            </component>
          </components>
        </bom>
      XML
    end

    it "parses CycloneDX XML content" do
      doc = REXML::Document.new(cyclonedx_xml_content)
      sbom = described_class.parse_xml(doc)

      # The result should be converted to a Reporter-compatible format
      expect(sbom).to be_a(Hash)
      expect(sbom["packages"]).to be_an(Array)
      expect(sbom["packages"].size).to eq(2)

      # Check first package
      rake_package = sbom["packages"].find { |p| p["name"] == "rake" }
      expect(rake_package).not_to be_nil
      expect(rake_package["versionInfo"]).to eq("13.0.6")
      expect(rake_package["licenseDeclared"]).to eq("MIT")

      # Check second package with multiple licenses
      bundler_package = sbom["packages"].find { |p| p["name"] == "bundler" }
      expect(bundler_package).not_to be_nil
      expect(bundler_package["versionInfo"]).to eq("2.4.0")
      expect(bundler_package["licenseDeclared"]).to eq("MIT, Apache-2.0")
    end
  end
end
