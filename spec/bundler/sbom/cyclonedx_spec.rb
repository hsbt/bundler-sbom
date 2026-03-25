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

  before(:each) do
    File.write("Gemfile", gemfile_content)
    File.write("Gemfile.lock", lockfile_content)

    # Set up default mocks
    allow(Bundler.default_lockfile).to receive(:exist?).and_return(true)
    allow(Bundler.default_lockfile).to receive(:read).and_return(lockfile_content)
  end

  describe ".generate" do
    it "generates CycloneDX SBOM instance" do
      sbom = described_class.generate([], "test-project")
      expect(sbom).to be_a(described_class)
      expect(sbom.to_hash["bomFormat"]).to eq("CycloneDX")
      expect(sbom.to_hash["specVersion"]).to eq("1.4")
      expect(sbom.to_hash["serialNumber"]).to match(/^urn:uuid:[0-9a-f-]+$/)
      expect(sbom.to_hash["components"]).to be_an(Array)
    end

    it "includes component information" do
      gem_data = [{name: "rake", version: "13.0.6", licenses: ["MIT"]}]
      sbom = described_class.generate(gem_data, "test-project")

      component = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
      expect(component).not_to be_nil
      expect(component["name"]).to eq("rake")
      expect(component["version"]).to eq("13.0.6")
      expect(component["type"]).to eq("library")
      expect(component["purl"]).to eq("pkg:gem/rake@13.0.6")
      expect(component["licenses"]).to be_an(Array)
      expect(component["licenses"].first["license"]["id"]).to eq("MIT")
    end

    it "handles multiple licenses" do
      gem_data = [{name: "bundler", version: "2.4.0", licenses: ["MIT", "Apache-2.0"]}]
      sbom = described_class.generate(gem_data, "test-project")

      component = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
      expect(component).not_to be_nil
      expect(component["licenses"].size).to eq(2)
      license_ids = component["licenses"].map { |l| l["license"]["id"] }
      expect(license_ids).to include("MIT")
      expect(license_ids).to include("Apache-2.0")
    end

    it "uses name field for non-SPDX license IDs" do
      gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}]
      sbom = described_class.generate(gem_data, "test-project")

      component = sbom.to_hash["components"].find { |c| c["name"] == "my-gem" }
      expect(component["licenses"]).to eq([{"license" => {"name" => "Nonstandard"}}])
    end

    it "maps deprecated SPDX license IDs to current equivalents" do
      gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["GPL-2.0"]}]
      sbom = described_class.generate(gem_data, "test-project")

      component = sbom.to_hash["components"].find { |c| c["name"] == "my-gem" }
      expect(component["licenses"]).to eq([{"license" => {"id" => "GPL-2.0-only"}}])
    end

    it "omits licenses array for packages with no license information" do
      gem_data = [{name: "no-license", version: "1.0.0", licenses: []}]
      sbom = described_class.generate(gem_data, "test-project")

      component = sbom.to_hash["components"].find { |c| c["name"] == "no-license" }
      expect(component).not_to be_nil
      expect(component["licenses"]).to be_nil
    end

    it "includes metadata with timestamp and tools" do
      sbom = described_class.generate([], "test-project")

      expect(sbom.to_hash["metadata"]).to be_a(Hash)
      expect(sbom.to_hash["metadata"]["timestamp"]).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
      expect(sbom.to_hash["metadata"]["tools"]).to be_an(Array)
      expect(sbom.to_hash["metadata"]["tools"].first["name"]).to eq("bundle-sbom")
    end
  end

  describe "#to_xml" do
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

    it "converts CycloneDX SBOM instance to XML format" do
      sbom = described_class.new(cyclonedx_hash)
      xml_content = sbom.to_xml
      expect(xml_content).to be_a(String)
      expect(xml_content).to include('<?xml version="1.0" encoding="UTF-8"?>')

      doc = REXML::Document.new(xml_content)
      root = doc.root

      expect(root.name).to eq("bom")
      expect(root.namespace).to include("cyclonedx.org/schema")
      expect(root.attributes["serialNumber"]).to eq("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")

      metadata = REXML::XPath.first(root, "metadata")
      expect(metadata).not_to be_nil
      expect(REXML::XPath.first(metadata, "timestamp").text).to eq("2023-01-01T12:00:00Z")

      tools = REXML::XPath.first(metadata, "tools")
      expect(tools).not_to be_nil
      tool = REXML::XPath.first(tools, "tool")
      expect(tool).not_to be_nil
      expect(REXML::XPath.first(tool, "name").text).to eq("bundle-sbom")

      components = REXML::XPath.first(root, "components")
      expect(components).not_to be_nil
      comps = REXML::XPath.each(components, "component").to_a
      expect(comps.size).to eq(2)

      comp1 = comps[0]
      expect(comp1.attributes["type"]).to eq("library")
      expect(REXML::XPath.first(comp1, "name").text).to eq("rake")
      expect(REXML::XPath.first(comp1, "version").text).to eq("13.0.6")
      expect(REXML::XPath.first(comp1, "purl").text).to eq("pkg:gem/rake@13.0.6")

      licenses1 = REXML::XPath.first(comp1, "licenses")
      expect(licenses1).not_to be_nil
      license1 = REXML::XPath.first(licenses1, "license")
      expect(license1).not_to be_nil
      expect(REXML::XPath.first(license1, "id").text).to eq("MIT")

      comp2 = comps[1]
      expect(comp2.attributes["type"]).to eq("library")
      expect(REXML::XPath.first(comp2, "name").text).to eq("bundler")

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

    it "parses CycloneDX XML content into instance" do
      doc = REXML::Document.new(cyclonedx_xml_content)
      sbom = described_class.parse_xml(doc)

      expect(sbom).to be_a(described_class)
      expect(sbom.to_hash["bomFormat"]).to eq("CycloneDX")
      expect(sbom.to_hash["components"]).to be_an(Array)
      expect(sbom.to_hash["components"].size).to eq(2)

      rake_comp = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
      expect(rake_comp).not_to be_nil
      expect(rake_comp["version"]).to eq("13.0.6")
      expect(rake_comp["licenses"]).to eq([{"license" => {"id" => "MIT"}}])

      bundler_comp = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
      expect(bundler_comp).not_to be_nil
      expect(bundler_comp["version"]).to eq("2.4.0")
      expect(bundler_comp["licenses"]).to eq([{"license" => {"id" => "MIT"}}, {"license" => {"id" => "Apache-2.0"}}])
    end
  end
end
