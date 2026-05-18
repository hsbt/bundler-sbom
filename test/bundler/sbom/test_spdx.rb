require "test_helper"
require "bundler/lockfile_parser"

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

    describes = sbom.to_hash["relationships"].select { |r| r["relationshipType"] == "DESCRIBES" }
    expected = [
      {
        "spdxElementId" => "SPDXRef-DOCUMENT",
        "relatedSpdxElement" => "SPDXRef-Package-rake",
        "relationshipType" => "DESCRIBES"
      }
    ]
    assert_equal expected, describes
  end

  def test_generate_includes_depends_on_relationships
    gem_data = [
      {name: "actionpack", version: "7.0.0", licenses: ["MIT"], dependencies: ["rack", "activesupport"]},
      {name: "rack", version: "3.0.0", licenses: ["MIT"], dependencies: []},
      {name: "activesupport", version: "7.0.0", licenses: ["MIT"], dependencies: ["tzinfo"]},
      {name: "tzinfo", version: "2.0.6", licenses: ["MIT"], dependencies: []}
    ]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    depends_on = sbom.to_hash["relationships"].select { |r| r["relationshipType"] == "DEPENDS_ON" }

    expected = [
      {"spdxElementId" => "SPDXRef-Package-actionpack", "relatedSpdxElement" => "SPDXRef-Package-rack", "relationshipType" => "DEPENDS_ON"},
      {"spdxElementId" => "SPDXRef-Package-actionpack", "relatedSpdxElement" => "SPDXRef-Package-activesupport", "relationshipType" => "DEPENDS_ON"},
      {"spdxElementId" => "SPDXRef-Package-activesupport", "relatedSpdxElement" => "SPDXRef-Package-tzinfo", "relationshipType" => "DEPENDS_ON"}
    ]
    assert_equal expected.sort_by { |r| [r["spdxElementId"], r["relatedSpdxElement"]] },
                 depends_on.sort_by { |r| [r["spdxElementId"], r["relatedSpdxElement"]] }
  end

  def test_generate_depends_on_ignores_unknown_names
    gem_data = [
      {name: "foo", version: "1.0.0", licenses: [], dependencies: ["bar", "missing"]},
      {name: "bar", version: "2.0.0", licenses: [], dependencies: []}
    ]
    sbom = Bundler::Sbom::SPDX.generate(gem_data, "test-project")

    depends_on = sbom.to_hash["relationships"].select { |r| r["relationshipType"] == "DEPENDS_ON" }
    assert_equal [{"spdxElementId" => "SPDXRef-Package-foo", "relatedSpdxElement" => "SPDXRef-Package-bar", "relationshipType" => "DEPENDS_ON"}], depends_on
  end

  def test_generate_license_list_version_from_gem
    sbom = Bundler::Sbom::SPDX.generate([], "test-project")
    version = sbom.to_hash["creationInfo"]["licenseListVersion"]
    refute_nil version
    assert_match(/\A\d+\.\d+/, version)
    refute_equal "3.20", version
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

  def test_spdx_does_not_support_xml
    sbom = Bundler::Sbom::SPDX.generate([], "test-project")
    refute_respond_to sbom, :to_xml
    refute_respond_to Bundler::Sbom::SPDX, :parse_xml
  end
end
