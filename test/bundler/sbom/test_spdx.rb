require "test_helper"
require "bundler/lockfile_parser"
require "rexml/document"

class Bundler::Sbom::SPDXTest < Minitest::Test
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

  def test_generate_sbom_instance
    sbom = Bundler::Sbom::SPDX.generate([], "test-project")
    assert_kind_of Bundler::Sbom::SPDX, sbom
    assert_equal "SPDXRef-DOCUMENT", sbom.to_hash["SPDXID"]
    assert_equal "SPDX-2.3", sbom.to_hash["spdxVersion"]
    assert_kind_of Array, sbom.to_hash["packages"]
  end

  def test_generate_includes_package_information
    gem_data = [{name: "rake", version: "13.0.6", licenses: ["MIT"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "rake" }
    refute_nil package
    assert_equal "rake", package["name"]
    assert_equal "13.0.6", package["versionInfo"]
    assert_equal "MIT", package["licenseDeclared"]
  end

  def test_generate_includes_describes_relationships
    gem_data = [{name: "rake", version: "13.0.6", licenses: ["MIT"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    relationships = sbom.to_hash["relationships"]
    expected = [
      {
        "spdxElementId" => "SPDXRef-DOCUMENT",
        "relatedSpdxElement" => "SPDXRef-Package-rake",
        "relationshipType" => "DESCRIBES"
      }
    ]
    assert_equal expected, relationships
  end

  def test_generate_handles_multiple_licenses
    gem_data = [{name: "bundler", version: "2.4.0", licenses: ["MIT", "Apache-2.0"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "bundler" }
    refute_nil package
    assert_equal "MIT AND Apache-2.0", package["licenseDeclared"]
  end

  def test_generate_normalizes_non_spdx_license_ids
    gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "my-gem" }
    assert_equal "LicenseRef-Nonstandard", package["licenseDeclared"]
  end

  def test_generate_maps_deprecated_spdx_license_ids
    gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["GPL-2.0"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "my-gem" }
    assert_equal "GPL-2.0-only", package["licenseDeclared"]
  end

  def test_generate_preserves_license_ref_prefix
    gem_data = [{name: "my-gem", version: "1.0.0", licenses: ["LicenseRef-custom"]}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "my-gem" }
    assert_equal "LicenseRef-custom", package["licenseDeclared"]
  end

  def test_generate_noassertion_for_no_license
    gem_data = [{name: "no-license", version: "1.0.0", licenses: []}]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    package = sbom.to_hash["packages"].find { |p| p["name"] == "no-license" }
    refute_nil package
    assert_equal "NOASSERTION", package["licenseDeclared"]
  end

  # -- #to_xml --

  def test_to_xml
    sbom_hash = {
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
      "relationships" => [
        {
          "spdxElementId" => "SPDXRef-DOCUMENT",
          "relatedSpdxElement" => "SPDXRef-Package-rake",
          "relationshipType" => "DESCRIBES"
        }
      ],
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
              "referenceCategory" => "PACKAGE-MANAGER",
              "referenceType" => "purl",
              "referenceLocator" => "pkg:gem/rake@13.0.6"
            }
          ]
        }
      ]
    }

    sbom = Bundler::Sbom::SPDX.new(sbom_hash)
    xml_content = sbom.to_xml
    assert_kind_of String, xml_content
    assert_includes xml_content, '<?xml version="1.0" encoding="UTF-8"?>'

    doc = REXML::Document.new(xml_content)
    root = doc.root

    assert_equal "SpdxDocument", root.name
    assert_equal "SPDXRef-DOCUMENT", REXML::XPath.first(root, "SPDXID").text
    assert_equal "SPDX-2.3", REXML::XPath.first(root, "spdxVersion").text
    assert_equal "test-project", REXML::XPath.first(root, "name").text

    package = REXML::XPath.first(root, "package")
    refute_nil package
    assert_equal "rake", REXML::XPath.first(package, "name").text
    assert_equal "13.0.6", REXML::XPath.first(package, "versionInfo").text
    assert_equal "MIT", REXML::XPath.first(package, "licenseDeclared").text

    ext_ref = REXML::XPath.first(package, "externalRef")
    refute_nil ext_ref
    assert_equal "pkg:gem/rake@13.0.6", REXML::XPath.first(ext_ref, "referenceLocator").text

    rel = REXML::XPath.first(root, "relationship")
    refute_nil rel
    assert_equal "SPDXRef-DOCUMENT", REXML::XPath.first(rel, "spdxElementId").text
    assert_equal "SPDXRef-Package-rake", REXML::XPath.first(rel, "relatedSpdxElement").text
    assert_equal "DESCRIBES", REXML::XPath.first(rel, "relationshipType").text
  end

  # -- .parse_xml --

  def test_parse_xml
    xml_content = <<~XML
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
            <referenceCategory>PACKAGE-MANAGER</referenceCategory>
            <referenceType>purl</referenceType>
            <referenceLocator>pkg:gem/rake@13.0.6</referenceLocator>
          </externalRef>
        </package>
        <relationship>
          <spdxElementId>SPDXRef-DOCUMENT</spdxElementId>
          <relatedSpdxElement>SPDXRef-Package-rake</relatedSpdxElement>
          <relationshipType>DESCRIBES</relationshipType>
        </relationship>
      </SpdxDocument>
    XML

    doc = REXML::Document.new(xml_content)
    sbom = Bundler::Sbom::SPDX.parse_xml(doc)

    assert_kind_of Bundler::Sbom::SPDX, sbom
    assert_equal "SPDXRef-DOCUMENT", sbom.to_hash["SPDXID"]
    assert_equal "SPDX-2.3", sbom.to_hash["spdxVersion"]
    assert_equal "test-project", sbom.to_hash["name"]
    assert_equal "CC0-1.0", sbom.to_hash["dataLicense"]

    assert_kind_of Hash, sbom.to_hash["creationInfo"]
    assert_equal "2023-01-01T12:00:00Z", sbom.to_hash["creationInfo"]["created"]
    assert_includes sbom.to_hash["creationInfo"]["creators"], "Tool: bundle-sbom"

    assert_kind_of Array, sbom.to_hash["packages"]
    assert_equal 1, sbom.to_hash["packages"].size

    package = sbom.to_hash["packages"].first
    assert_equal "SPDXRef-Package-rake", package["SPDXID"]
    assert_equal "rake", package["name"]
    assert_equal "13.0.6", package["versionInfo"]
    assert_equal "MIT", package["licenseDeclared"]

    assert_kind_of Array, package["externalRefs"]
    assert_equal 1, package["externalRefs"].size

    ext_ref = package["externalRefs"].first
    assert_equal "PACKAGE-MANAGER", ext_ref["referenceCategory"]
    assert_equal "purl", ext_ref["referenceType"]
    assert_equal "pkg:gem/rake@13.0.6", ext_ref["referenceLocator"]

    relationships = sbom.to_hash["relationships"]
    assert_equal 1, relationships.size
    assert_equal "SPDXRef-DOCUMENT", relationships.first["spdxElementId"]
    assert_equal "SPDXRef-Package-rake", relationships.first["relatedSpdxElement"]
    assert_equal "DESCRIBES", relationships.first["relationshipType"]
  end
end
