require "test_helper"
require "json"
require "fileutils"

class Bundler::Sbom::CLITest < Minitest::Test
  include TestHelper

  def setup
    super
    @temp_dir = Dir.mktmpdir
    @original_dir = Dir.pwd
    Dir.chdir(@temp_dir)
  end

  def teardown
    Dir.chdir(@original_dir)
    FileUtils.remove_entry(@temp_dir) if Dir.exist?(@temp_dir)
  end

  def sample_spdx_sbom
    {
      "SPDXID" => "SPDXRef-DOCUMENT",
      "packages" => [
        {"name" => "rake", "versionInfo" => "13.0.6", "licenseDeclared" => "MIT"}
      ]
    }
  end

  def sample_cyclonedx_sbom
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.4",
      "serialNumber" => "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version" => 1,
      "components" => [
        {"name" => "rake", "version" => "13.0.6", "type" => "library"}
      ]
    }
  end

  # -- dump tests --

  def test_dump_default_format_generates_spdx_json
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    mock_generator = Minitest::Mock.new
    mock_generator.expect(:generate, spdx_instance)

    Bundler::Sbom::Generator.stub(:new, mock_generator) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump]) }
    end

    assert File.exist?("bom.json"), "bom.json should be created"
    parsed = JSON.parse(File.read("bom.json"))
    assert_equal sample_spdx_sbom, parsed
    mock_generator.verify
  end

  def test_dump_xml_format_generates_spdx_xml
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    xml_output = "<xml>spdx</xml>"
    spdx_instance.define_singleton_method(:to_xml) { xml_output }

    mock_generator = Minitest::Mock.new
    mock_generator.expect(:generate, spdx_instance)

    Bundler::Sbom::Generator.stub(:new, mock_generator) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --format xml]) }
    end

    assert File.exist?("bom.xml"), "bom.xml should be created"
    assert_equal xml_output, File.read("bom.xml")
    mock_generator.verify
  end

  def test_dump_cyclonedx_json
    cyclonedx_instance = Bundler::Sbom::CycloneDX.new(sample_cyclonedx_sbom)
    mock_generator = Minitest::Mock.new
    mock_generator.expect(:generate, cyclonedx_instance)

    Bundler::Sbom::Generator.stub(:new, mock_generator) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --sbom cyclonedx]) }
    end

    assert File.exist?("bom-cyclonedx.json"), "bom-cyclonedx.json should be created"
    parsed = JSON.parse(File.read("bom-cyclonedx.json"))
    assert_equal sample_cyclonedx_sbom, parsed
    mock_generator.verify
  end

  def test_dump_cyclonedx_xml
    cyclonedx_instance = Bundler::Sbom::CycloneDX.new(sample_cyclonedx_sbom)
    xml_output = "<xml>cyclonedx</xml>"
    cyclonedx_instance.define_singleton_method(:to_xml) { xml_output }

    mock_generator = Minitest::Mock.new
    mock_generator.expect(:generate, cyclonedx_instance)

    Bundler::Sbom::Generator.stub(:new, mock_generator) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --format xml --sbom cyclonedx]) }
    end

    assert File.exist?("bom-cyclonedx.xml"), "bom-cyclonedx.xml should be created"
    assert_equal xml_output, File.read("bom-cyclonedx.xml")
    mock_generator.verify
  end

  def test_dump_invalid_output_format_exits
    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --format invalid]) }
    end
  end

  def test_dump_invalid_sbom_format_exits
    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --sbom invalid]) }
    end
  end

  def test_dump_with_without_single_group
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, spdx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --without development]) }
    end

    assert_equal({format: "spdx", without_groups: [:development]}, received_args)
  end

  def test_dump_with_without_colon_separated_groups
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, spdx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --without development:test]) }
    end

    assert_equal({format: "spdx", without_groups: [:development, :test]}, received_args)
  end

  def test_dump_with_without_comma_separated_groups
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, spdx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --without development,test]) }
    end

    assert_equal({format: "spdx", without_groups: [:development, :test]}, received_args)
  end

  def test_dump_with_without_mixed_separators
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, spdx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --without development:test,staging]) }
    end

    assert_equal({format: "spdx", without_groups: [:development, :test, :staging]}, received_args)
  end

  def test_dump_with_without_ignores_empty_groups
    spdx_instance = Bundler::Sbom::SPDX.new(sample_spdx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, spdx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --without development::test]) }
    end

    assert_equal({format: "spdx", without_groups: [:development, :test]}, received_args)
  end

  def test_dump_with_without_cyclonedx
    cyclonedx_instance = Bundler::Sbom::CycloneDX.new(sample_cyclonedx_sbom)
    received_args = nil
    fake_new = proc do |**kwargs|
      received_args = kwargs
      mock_gen = Minitest::Mock.new
      mock_gen.expect(:generate, cyclonedx_instance)
      mock_gen
    end

    Bundler::Sbom::Generator.stub(:new, fake_new) do
      capture_io { Bundler::Sbom::CLI.start(%w[dump --sbom cyclonedx --without development]) }
    end

    assert_equal({format: "cyclonedx", without_groups: [:development]}, received_args)
  end

  # -- license tests --

  def test_license_reads_bom_json
    File.write("bom.json", JSON.generate(sample_spdx_sbom))

    out, = capture_io { Bundler::Sbom::CLI.start(%w[license]) }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_license_reads_cyclonedx_json_when_bom_json_missing
    File.write("bom-cyclonedx.json", JSON.generate(sample_cyclonedx_sbom))

    out, = capture_io { Bundler::Sbom::CLI.start(%w[license]) }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_license_reads_cyclonedx_xml_when_json_missing
    cyclonedx_xml = <<~XML
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
            <licenses>
              <license>
                <id>MIT</id>
              </license>
            </licenses>
          </component>
        </components>
      </bom>
    XML
    File.write("bom-cyclonedx.xml", cyclonedx_xml)

    out, = capture_io { Bundler::Sbom::CLI.start(%w[license]) }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_license_reads_xml_format
    spdx_xml = <<~XML
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
        <package>
          <SPDXID>SPDXRef-Package-rake</SPDXID>
          <name>rake</name>
          <versionInfo>13.0.6</versionInfo>
          <licenseDeclared>MIT</licenseDeclared>
        </package>
      </SpdxDocument>
    XML
    File.write("bom.xml", spdx_xml)

    out, = capture_io { Bundler::Sbom::CLI.start(%w[license --format xml]) }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_license_xml_invalid_exits
    File.write("bom.xml", "<invalid>XML Content")

    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[license --format xml]) }
    end
  end

  def test_license_with_specific_file_path
    File.write("custom-bom.json", JSON.generate(sample_cyclonedx_sbom))

    out, = capture_io { Bundler::Sbom::CLI.start(%w[license --file custom-bom.json]) }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_license_no_sbom_files_exits
    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[license]) }
    end
  end

  def test_license_invalid_json_exits
    File.write("bom.json", "invalid json content")

    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[license]) }
    end
  end

  def test_license_invalid_format_exits
    assert_raises(SystemExit) do
      capture_io { Bundler::Sbom::CLI.start(%w[license --format invalid]) }
    end
  end
end
