require "test_helper"
require "bundler/lockfile_parser"
require "rexml/document"

class Bundler::Sbom::CycloneDXTest < Minitest::Test
  include TestHelper

  def setup
    super
    @temp_dir = Dir.mktmpdir
    @original_dir = Dir.pwd
    Dir.chdir(@temp_dir)

    @gemfile_content = <<~GEMFILE
      source "https://rubygems.org"
      gem "rake"
    GEMFILE

    @lockfile_content = <<~LOCKFILE
      GEM
        remote: https://rubygems.org/
        specs:
          rake (13.0.6)

      PLATFORMS
        ruby

      DEPENDENCIES
        rake
    LOCKFILE

    File.write("Gemfile", @gemfile_content)
    File.write("Gemfile.lock", @lockfile_content)
  end

  def teardown
    Dir.chdir(@original_dir)
    FileUtils.remove_entry(@temp_dir) if Dir.exist?(@temp_dir)
  end

  # -- .generate tests --

  def test_generate_cyclonedx_instance
    sbom = Bundler::Sbom::CycloneDX.generate([], "test-project")
    assert_kind_of Bundler::Sbom::CycloneDX, sbom
    assert_equal "CycloneDX", sbom.to_hash["bomFormat"]
    assert_equal "1.4", sbom.to_hash["specVersion"]
    assert_match(/^urn:uuid:[0-9a-f-]+$/, sbom.to_hash["serialNumber"])
    assert_kind_of Array, sbom.to_hash["components"]
  end

  def test_generate_includes_component_information
    gem_data = [{name: "rake", version: "13.0.6", licenses: ["MIT"]}]
    sbom = Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")

    component = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
    refute_nil component
    assert_equal "rake", component["name"]
    assert_equal "13.0.6", component["version"]
    assert_equal "library", component["type"]
    assert_equal "pkg:gem/rake@13.0.6", component["purl"]
    assert_kind_of Array, component["licenses"]
    assert_equal "MIT", component["licenses"].first["license"]["id"]
  end

  def test_generate_handles_multiple_licenses
    gem_data = [{name: "bundler", version: "2.4.0", licenses: ["MIT", "Apache-2.0"]}]
    sbom = Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")

    component = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
    refute_nil component
    assert_equal 2, component["licenses"].size
    license_ids = component["licenses"].map { |l| l["license"]["id"] }
    assert_includes license_ids, "MIT"
    assert_includes license_ids, "Apache-2.0"
  end

  def test_generate_uses_name_for_non_spdx_license_ids
    gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}]
    sbom = Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")

    component = sbom.to_hash["components"].find { |c| c["name"] == "my-gem" }
    assert_equal [{"license" => {"name" => "Nonstandard"}}], component["licenses"]
  end

  def test_generate_maps_deprecated_spdx_license_ids
    gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["GPL-2.0"]}]
    sbom = Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")

    component = sbom.to_hash["components"].find { |c| c["name"] == "my-gem" }
    assert_equal [{"license" => {"id" => "GPL-2.0-only"}}], component["licenses"]
  end

  def test_generate_omits_licenses_for_no_license
    gem_data = [{name: "no-license", version: "1.0.0", licenses: []}]
    sbom = Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")

    component = sbom.to_hash["components"].find { |c| c["name"] == "no-license" }
    refute_nil component
    assert_nil component["licenses"]
  end

  def test_generate_includes_metadata
    sbom = Bundler::Sbom::CycloneDX.generate([], "test-project")

    assert_kind_of Hash, sbom.to_hash["metadata"]
    assert_match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/, sbom.to_hash["metadata"]["timestamp"])
    assert_kind_of Array, sbom.to_hash["metadata"]["tools"]
    assert_equal "bundle-sbom", sbom.to_hash["metadata"]["tools"].first["name"]
  end

  # -- #to_xml --

  def test_to_xml
    cyclonedx_hash = {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version" => 1,
      "metadata" => {
        "timestamp" => "2023-01-01T12:00:00Z",
        "tools" => [
          {"vendor" => "Bundler", "name" => "bundle-sbom", "version" => "0.1.0"}
        ],
        "component" => {
          "type" => "application", "name" => "test-project", "version" => "0.0.0"
        }
      },
      "components" => [
        {
          "type" => "library", "name" => "rake", "version" => "13.0.6",
          "purl" => "pkg:gem/rake@13.0.6",
          "licenses" => [{"license" => {"id" => "MIT"}}]
        },
        {
          "type" => "library", "name" => "bundler", "version" => "2.4.0",
          "purl" => "pkg:gem/bundler@2.4.0",
          "licenses" => [
            {"license" => {"id" => "MIT"}},
            {"license" => {"id" => "Apache-2.0"}}
          ]
        },
        {
          "type" => "library", "name" => "custom-gem", "version" => "1.0.0",
          "purl" => "pkg:gem/custom-gem@1.0.0",
          "licenses" => [{"license" => {"name" => "Custom License"}}]
        }
      ]
    }

    sbom = Bundler::Sbom::CycloneDX.new(cyclonedx_hash)
    xml_content = sbom.to_xml
    assert_kind_of String, xml_content
    assert_includes xml_content, '<?xml version="1.0" encoding="UTF-8"?>'

    doc = REXML::Document.new(xml_content)
    root = doc.root

    assert_equal "bom", root.name
    assert_includes root.namespace, "cyclonedx.org/schema"
    assert_equal "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", root.attributes["serialNumber"]

    metadata = REXML::XPath.first(root, "metadata")
    refute_nil metadata
    assert_equal "2023-01-01T12:00:00Z", REXML::XPath.first(metadata, "timestamp").text

    tools = REXML::XPath.first(metadata, "tools")
    refute_nil tools
    tool = REXML::XPath.first(tools, "tool")
    refute_nil tool
    assert_equal "bundle-sbom", REXML::XPath.first(tool, "name").text

    components = REXML::XPath.first(root, "components")
    refute_nil components
    comps = REXML::XPath.each(components, "component").to_a
    assert_equal 3, comps.size

    comp1 = comps[0]
    assert_equal "library", comp1.attributes["type"]
    assert_equal "rake", REXML::XPath.first(comp1, "name").text
    assert_equal "13.0.6", REXML::XPath.first(comp1, "version").text
    assert_equal "pkg:gem/rake@13.0.6", REXML::XPath.first(comp1, "purl").text

    licenses1 = REXML::XPath.first(comp1, "licenses")
    refute_nil licenses1
    license1 = REXML::XPath.first(licenses1, "license")
    refute_nil license1
    assert_equal "MIT", REXML::XPath.first(license1, "id").text

    comp2 = comps[1]
    assert_equal "library", comp2.attributes["type"]
    assert_equal "bundler", REXML::XPath.first(comp2, "name").text

    licenses2 = REXML::XPath.first(comp2, "licenses")
    refute_nil licenses2
    license_nodes = REXML::XPath.each(licenses2, "license").to_a
    assert_equal 2, license_nodes.size
    license_ids = license_nodes.map { |node| REXML::XPath.first(node, "id").text }
    assert_includes license_ids, "MIT"
    assert_includes license_ids, "Apache-2.0"

    comp3 = comps[2]
    assert_equal "custom-gem", REXML::XPath.first(comp3, "name").text
    licenses3 = REXML::XPath.first(comp3, "licenses")
    license3 = REXML::XPath.first(licenses3, "license")
    assert_equal "Custom License", REXML::XPath.first(license3, "name").text
    assert_nil REXML::XPath.first(license3, "id")
  end

  # -- .parse_xml --

  def test_parse_xml
    cyclonedx_xml_content = <<~XML
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
          <component type="library">
            <name>custom-gem</name>
            <version>1.0.0</version>
            <purl>pkg:gem/custom-gem@1.0.0</purl>
            <licenses>
              <license>
                <name>Custom License</name>
              </license>
            </licenses>
          </component>
        </components>
      </bom>
    XML

    doc = REXML::Document.new(cyclonedx_xml_content)
    sbom = Bundler::Sbom::CycloneDX.parse_xml(doc)

    assert_kind_of Bundler::Sbom::CycloneDX, sbom
    assert_equal "CycloneDX", sbom.to_hash["bomFormat"]
    assert_kind_of Array, sbom.to_hash["components"]
    assert_equal 3, sbom.to_hash["components"].size

    rake_comp = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
    refute_nil rake_comp
    assert_equal "13.0.6", rake_comp["version"]
    assert_equal [{"license" => {"id" => "MIT"}}], rake_comp["licenses"]

    bundler_comp = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
    refute_nil bundler_comp
    assert_equal "2.4.0", bundler_comp["version"]
    assert_equal [{"license" => {"id" => "MIT"}}, {"license" => {"id" => "Apache-2.0"}}], bundler_comp["licenses"]

    custom_comp = sbom.to_hash["components"].find { |c| c["name"] == "custom-gem" }
    refute_nil custom_comp
    assert_equal [{"license" => {"name" => "Custom License"}}], custom_comp["licenses"]
  end
end
