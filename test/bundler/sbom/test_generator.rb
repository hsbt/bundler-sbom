require "test_helper"
require "bundler/lockfile_parser"
require "rexml/document"

class Bundler::Sbom::GeneratorTest < Minitest::Test
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

  def rake_spec
    spec = Object.new
    spec.define_singleton_method(:name) { "rake" }
    spec.define_singleton_method(:version) { Gem::Version.new("13.0.6") }
    spec.define_singleton_method(:license) { "MIT" }
    spec.define_singleton_method(:licenses) { ["MIT"] }
    spec
  end

  def multi_license_spec
    spec = Object.new
    spec.define_singleton_method(:name) { "bundler" }
    spec.define_singleton_method(:version) { Gem::Version.new("2.4.0") }
    spec.define_singleton_method(:license) { "" }
    spec.define_singleton_method(:licenses) { ["MIT", "Apache-2.0"] }
    spec
  end

  def empty_license_spec
    spec = Object.new
    spec.define_singleton_method(:name) { "no-license" }
    spec.define_singleton_method(:version) { Gem::Version.new("1.0.0") }
    spec.define_singleton_method(:license) { "" }
    spec.define_singleton_method(:licenses) { [] }
    spec
  end

  def nil_license_spec
    spec = Object.new
    spec.define_singleton_method(:name) { "nil-license" }
    spec.define_singleton_method(:version) { Gem::Version.new("1.0.0") }
    spec.define_singleton_method(:license) { nil }
    spec.define_singleton_method(:licenses) { nil }
    spec
  end

  def make_spec(name, version)
    s = Object.new
    s.define_singleton_method(:name) { name }
    s.define_singleton_method(:version) { Gem::Version.new(version) }
    s
  end

  def make_lockfile_parser(specs)
    parser = Object.new
    parser.define_singleton_method(:specs) { specs }
    parser
  end

  def stub_lockfile_and_gems(specs, gem_specs = {})
    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(specs)) do
        Gem::Specification.stub(:find_by_name, proc { |name, version|
          gem_specs[[name, version]] || gem_specs[:default]
        }) do
          yield
        end
      end
    end
  end

  # -- SPDX format tests --

  def test_generate_spdx_document
    stub_lockfile_and_gems([], default: nil) do
      sbom = Bundler::Sbom::Generator.new.generate
      assert_kind_of Bundler::Sbom::SPDX, sbom
      assert_equal "SPDXRef-DOCUMENT", sbom.to_hash["SPDXID"]
      assert_equal "SPDX-2.3", sbom.to_hash["spdxVersion"]
      assert_kind_of Array, sbom.to_hash["packages"]
    end
  end

  def test_generate_spdx_includes_package_info
    specs = [make_spec("rake", "13.0.6")]
    gem_specs = {["rake", Gem::Version.new("13.0.6")] => rake_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new.generate
      package = sbom.to_hash["packages"].find { |p| p["name"] == "rake" }
      refute_nil package
      assert_equal "rake", package["name"]
      assert_equal "13.0.6", package["versionInfo"]
      assert_equal "MIT", package["licenseDeclared"]
    end
  end

  def test_generate_spdx_handles_multiple_licenses
    specs = [make_spec("bundler", "2.4.0")]
    gem_specs = {["bundler", Gem::Version.new("2.4.0")] => multi_license_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new.generate
      package = sbom.to_hash["packages"].find { |p| p["name"] == "bundler" }
      refute_nil package
      assert_equal "MIT AND Apache-2.0", package["licenseDeclared"]
    end
  end

  def test_generate_spdx_noassertion_for_no_license
    specs = [make_spec("no-license", "1.0.0")]
    gem_specs = {["no-license", Gem::Version.new("1.0.0")] => empty_license_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new.generate
      package = sbom.to_hash["packages"].find { |p| p["name"] == "no-license" }
      refute_nil package
      assert_equal "NOASSERTION", package["licenseDeclared"]
    end
  end

  def test_generate_spdx_handles_nil_license
    specs = [make_spec("nil-license", "1.0.0")]
    gem_specs = {["nil-license", Gem::Version.new("1.0.0")] => nil_license_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new.generate
      package = sbom.to_hash["packages"].find { |p| p["name"] == "nil-license" }
      refute_nil package
      assert_equal "NOASSERTION", package["licenseDeclared"]
    end
  end

  def test_generate_spdx_handles_gem_load_error
    specs = [make_spec("missing-gem", "1.0.0")]

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(specs)) do
        Gem::Specification.stub(:find_by_name, proc { raise Gem::LoadError }) do
          sbom = Bundler::Sbom::Generator.new.generate
          package = sbom.to_hash["packages"].find { |p| p["name"] == "missing-gem" }
          refute_nil package
          assert_equal "NOASSERTION", package["licenseDeclared"]
        end
      end
    end
  end

  def test_generate_spdx_deduplicates_gems
    specs = [
      make_spec("herb", "1.0.0"),
      make_spec("herb", "1.0.0"),
      make_spec("herb", "1.0.0"),
      make_spec("rake", "13.0.6")
    ]

    stub_lockfile_and_gems(specs, default: nil) do
      sbom = Bundler::Sbom::Generator.new.generate
      assert_equal 2, sbom.to_hash["packages"].size
      assert_equal 2, sbom.to_hash["documentDescribes"].size

      herb_packages = sbom.to_hash["packages"].select { |p| p["name"] == "herb" }
      assert_equal 1, herb_packages.size

      rake_packages = sbom.to_hash["packages"].select { |p| p["name"] == "rake" }
      assert_equal 1, rake_packages.size
    end
  end

  def test_generate_spdx_filters_excluded_groups
    development_gem = make_spec("rspec", "3.12.0")
    production_gem = make_spec("rails", "7.0.0")
    all_specs = [production_gem, development_gem]

    definition = Object.new
    definition.define_singleton_method(:groups) { [:default, :development] }
    definition.define_singleton_method(:dependencies_for) { |group|
      case group
      when :default then [Object.new.tap { |o| o.define_singleton_method(:name) { "rails" } }]
      when :development then [Object.new.tap { |o| o.define_singleton_method(:name) { "rspec" } }]
      end
    }

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(all_specs)) do
        Bundler.stub(:definition, definition) do
          Gem::Specification.stub(:find_by_name, proc { nil }) do
            sbom = Bundler::Sbom::Generator.new(format: "spdx", without_groups: [:development]).generate
            assert_equal 1, sbom.to_hash["packages"].size
            assert_equal "rails", sbom.to_hash["packages"].first["name"]
          end
        end
      end
    end
  end

  def test_generate_spdx_includes_transitive_dependencies
    rails_gem = make_spec("rails", "7.0.0")
    activesupport_gem = make_spec("activesupport", "7.0.0")
    rspec_gem = make_spec("rspec", "3.12.0")
    diff_lcs_gem = make_spec("diff-lcs", "1.5.0")
    all_specs = [rails_gem, activesupport_gem, rspec_gem, diff_lcs_gem]

    definition = Object.new
    definition.define_singleton_method(:groups) { [:default, :development] }
    definition.define_singleton_method(:dependencies_for) { |group|
      case group
      when :default then [Object.new.tap { |o| o.define_singleton_method(:name) { "rails" } }]
      when :development then [Object.new.tap { |o| o.define_singleton_method(:name) { "rspec" } }]
      end
    }
    definition.define_singleton_method(:specs_for) { |groups|
      [rails_gem, activesupport_gem]
    }

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(all_specs)) do
        Bundler.stub(:definition, definition) do
          Gem::Specification.stub(:find_by_name, proc { nil }) do
            sbom = Bundler::Sbom::Generator.new(format: "spdx", without_groups: [:development]).generate
            package_names = sbom.to_hash["packages"].map { |p| p["name"] }
            assert_includes package_names, "rails"
            assert_includes package_names, "activesupport"
            assert_equal 2, package_names.size
          end
        end
      end
    end
  end

  def test_generate_spdx_excludes_transitive_dependencies_of_excluded_groups
    rails_gem = make_spec("rails", "7.0.0")
    rspec_gem = make_spec("rspec", "3.12.0")
    diff_lcs_gem = make_spec("diff-lcs", "1.5.0")
    all_specs = [rails_gem, rspec_gem, diff_lcs_gem]

    definition = Object.new
    definition.define_singleton_method(:groups) { [:default, :development] }
    definition.define_singleton_method(:dependencies_for) { |group|
      case group
      when :default then [Object.new.tap { |o| o.define_singleton_method(:name) { "rails" } }]
      when :development then [Object.new.tap { |o| o.define_singleton_method(:name) { "rspec" } }]
      end
    }
    definition.define_singleton_method(:specs_for) { |groups| [rails_gem] }

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(all_specs)) do
        Bundler.stub(:definition, definition) do
          Gem::Specification.stub(:find_by_name, proc { nil }) do
            sbom = Bundler::Sbom::Generator.new(format: "spdx", without_groups: [:development]).generate
            package_names = sbom.to_hash["packages"].map { |p| p["name"] }
            assert_equal ["rails"], package_names
          end
        end
      end
    end
  end

  def test_generate_spdx_handles_shared_transitive_dependencies
    rails_gem = make_spec("rails", "7.0.0")
    rspec_gem = make_spec("rspec", "3.12.0")
    minitest_gem = make_spec("minitest", "5.18.0")
    activesupport_gem = make_spec("activesupport", "7.0.0")
    all_specs = [rails_gem, rspec_gem, minitest_gem, activesupport_gem]

    definition = Object.new
    definition.define_singleton_method(:groups) { [:default, :development, :test] }
    definition.define_singleton_method(:dependencies_for) { |group|
      case group
      when :default then [Object.new.tap { |o| o.define_singleton_method(:name) { "rails" } }]
      when :development then [Object.new.tap { |o| o.define_singleton_method(:name) { "rspec" } }]
      when :test then [Object.new.tap { |o| o.define_singleton_method(:name) { "minitest" } }]
      end
    }
    definition.define_singleton_method(:specs_for) { |groups|
      [rails_gem, minitest_gem, activesupport_gem]
    }

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(all_specs)) do
        Bundler.stub(:definition, definition) do
          Gem::Specification.stub(:find_by_name, proc { nil }) do
            sbom = Bundler::Sbom::Generator.new(format: "spdx", without_groups: [:development]).generate
            package_names = sbom.to_hash["packages"].map { |p| p["name"] }
            assert_includes package_names, "rails"
            assert_includes package_names, "minitest"
            assert_includes package_names, "activesupport"
            assert_equal 3, package_names.size
          end
        end
      end
    end
  end

  # -- CycloneDX format tests --

  def test_generate_cyclonedx_document
    stub_lockfile_and_gems([], default: nil) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      assert_kind_of Bundler::Sbom::CycloneDX, sbom
      assert_equal "CycloneDX", sbom.to_hash["bomFormat"]
      assert_equal "1.4", sbom.to_hash["specVersion"]
      assert_match(/^urn:uuid:[0-9a-f-]+$/, sbom.to_hash["serialNumber"])
      assert_kind_of Array, sbom.to_hash["components"]
    end
  end

  def test_generate_cyclonedx_includes_component_info
    specs = [make_spec("rake", "13.0.6")]
    gem_specs = {["rake", Gem::Version.new("13.0.6")] => rake_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      component = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
      refute_nil component
      assert_equal "rake", component["name"]
      assert_equal "13.0.6", component["version"]
      assert_equal "library", component["type"]
      assert_equal "pkg:gem/rake@13.0.6", component["purl"]
      assert_kind_of Array, component["licenses"]
      assert_equal "MIT", component["licenses"].first["license"]["id"]
    end
  end

  def test_generate_cyclonedx_handles_multiple_licenses
    specs = [make_spec("bundler", "2.4.0")]
    gem_specs = {["bundler", Gem::Version.new("2.4.0")] => multi_license_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      component = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
      refute_nil component
      assert_equal 2, component["licenses"].size
      license_ids = component["licenses"].map { |l| l["license"]["id"] }
      assert_includes license_ids, "MIT"
      assert_includes license_ids, "Apache-2.0"
    end
  end

  def test_generate_cyclonedx_omits_licenses_for_no_license
    specs = [make_spec("no-license", "1.0.0")]
    gem_specs = {["no-license", Gem::Version.new("1.0.0")] => empty_license_spec}

    stub_lockfile_and_gems(specs, gem_specs) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      component = sbom.to_hash["components"].find { |c| c["name"] == "no-license" }
      refute_nil component
      assert_nil component["licenses"]
    end
  end

  def test_generate_cyclonedx_includes_metadata
    stub_lockfile_and_gems([], default: nil) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      assert_kind_of Hash, sbom.to_hash["metadata"]
      assert_match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/, sbom.to_hash["metadata"]["timestamp"])
      assert_kind_of Array, sbom.to_hash["metadata"]["tools"]
      assert_equal "bundle-sbom", sbom.to_hash["metadata"]["tools"].first["name"]
    end
  end

  def test_generate_cyclonedx_deduplicates_gems
    specs = [
      make_spec("herb", "1.0.0"),
      make_spec("herb", "1.0.0"),
      make_spec("herb", "1.0.0"),
      make_spec("rake", "13.0.6")
    ]

    stub_lockfile_and_gems(specs, default: nil) do
      sbom = Bundler::Sbom::Generator.new(format: "cyclonedx").generate
      assert_equal 2, sbom.to_hash["components"].size

      herb_components = sbom.to_hash["components"].select { |c| c["name"] == "herb" }
      assert_equal 1, herb_components.size

      rake_components = sbom.to_hash["components"].select { |c| c["name"] == "rake" }
      assert_equal 1, rake_components.size
    end
  end

  def test_generate_cyclonedx_filters_excluded_groups
    development_gem = make_spec("rspec", "3.12.0")
    production_gem = make_spec("rails", "7.0.0")
    all_specs = [production_gem, development_gem]

    definition = Object.new
    definition.define_singleton_method(:groups) { [:default, :development] }
    definition.define_singleton_method(:dependencies_for) { |group|
      case group
      when :default then [Object.new.tap { |o| o.define_singleton_method(:name) { "rails" } }]
      when :development then [Object.new.tap { |o| o.define_singleton_method(:name) { "rspec" } }]
      end
    }

    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { true }
    mock_lockfile.define_singleton_method(:read) { @lockfile_content }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      Bundler::LockfileParser.stub(:new, make_lockfile_parser(all_specs)) do
        Bundler.stub(:definition, definition) do
          Gem::Specification.stub(:find_by_name, proc { nil }) do
            sbom = Bundler::Sbom::Generator.new(format: "cyclonedx", without_groups: [:development]).generate
            assert_equal 1, sbom.to_hash["components"].size
            assert_equal "rails", sbom.to_hash["components"].first["name"]
          end
        end
      end
    end
  end

  # -- Gemfile.lock missing --

  def test_generate_raises_when_no_lockfile
    FileUtils.rm("Gemfile.lock") if File.exist?("Gemfile.lock")
    mock_lockfile = Object.new
    mock_lockfile.define_singleton_method(:exist?) { false }

    Bundler.stub(:default_lockfile, mock_lockfile) do
      assert_raises(Bundler::Sbom::GemfileLockNotFoundError) do
        Bundler::Sbom::Generator.new.generate
      end
    end
  end

  # -- to_xml SPDX --

  def test_spdx_to_xml
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
  end

  # -- to_xml CycloneDX --

  def test_cyclonedx_to_xml
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
    assert_equal 2, comps.size

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
  end

  # -- parse_xml SPDX --

  def test_parse_xml_spdx
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
      </SpdxDocument>
    XML

    sbom = Bundler::Sbom::Generator.parse_xml(xml_content)

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
  end

  # -- parse_xml CycloneDX --

  def test_parse_xml_cyclonedx
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
        </components>
      </bom>
    XML

    sbom = Bundler::Sbom::Generator.parse_xml(cyclonedx_xml_content)

    assert_kind_of Bundler::Sbom::CycloneDX, sbom
    assert_equal "CycloneDX", sbom.to_hash["bomFormat"]
    assert_kind_of Array, sbom.to_hash["components"]
    assert_equal 2, sbom.to_hash["components"].size

    rake_comp = sbom.to_hash["components"].find { |c| c["name"] == "rake" }
    refute_nil rake_comp
    assert_equal "13.0.6", rake_comp["version"]
    assert_equal [{"license" => {"id" => "MIT"}}], rake_comp["licenses"]

    bundler_comp = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
    refute_nil bundler_comp
    assert_equal "2.4.0", bundler_comp["version"]
    assert_equal [{"license" => {"id" => "MIT"}}, {"license" => {"id" => "Apache-2.0"}}], bundler_comp["licenses"]
  end

  def test_parse_xml_malformed_raises
    malformed_xml = "<invalid>XML Content"
    assert_raises(REXML::ParseException) do
      Bundler::Sbom::Generator.parse_xml(malformed_xml)
    end
  end

  # -- from_hash --

  def test_from_hash_returns_spdx_for_spdx_hash
    sbom = Bundler::Sbom::Generator.from_hash({"SPDXID" => "SPDXRef-DOCUMENT", "packages" => []})
    assert_kind_of Bundler::Sbom::SPDX, sbom
  end

  def test_from_hash_returns_cyclonedx_for_cyclonedx_hash
    sbom = Bundler::Sbom::Generator.from_hash({"bomFormat" => "CycloneDX", "components" => []})
    assert_kind_of Bundler::Sbom::CycloneDX, sbom
  end
end
