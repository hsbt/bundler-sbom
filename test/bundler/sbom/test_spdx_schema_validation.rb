require "test_helper"
require "json_schemer"

class SPDXSchemaValidationTest < Minitest::Test
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

  def schema
    schema_path = File.join(TestHelper.root, "test", "fixtures", "spdx-schema.json")
    JSONSchemer.schema(Pathname.new(schema_path))
  end

  def generate_sbom(gem_data)
    Bundler::Sbom::SPDX.generate(gem_data, "test-project")
  end

  def test_valid_spdx_document_with_single_gem
    sbom = generate_sbom([{name: "rake", version: "13.0.6", licenses: ["MIT"]}])
    errors = schema.validate(sbom.to_hash).to_a
    assert_empty errors, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n")
  end

  def test_valid_spdx_document_with_multiple_gems
    gem_data = [
      {name: "rake", version: "13.0.6", licenses: ["MIT"]},
      {name: "rspec", version: "3.12.0", licenses: ["MIT"]},
      {name: "rails", version: "7.0.0", licenses: ["MIT", "Apache-2.0"]}
    ]
    sbom = generate_sbom(gem_data)
    errors = schema.validate(sbom.to_hash).to_a
    assert_empty errors, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n")
  end

  def test_valid_spdx_document_with_no_license
    sbom = generate_sbom([{name: "unknown-gem", version: "1.0.0", licenses: []}])
    errors = schema.validate(sbom.to_hash).to_a
    assert_empty errors, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n")
  end

  def test_valid_spdx_document_with_non_spdx_license_ids
    sbom = generate_sbom([{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}])
    errors = schema.validate(sbom.to_hash).to_a
    assert_empty errors, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n")
  end

  def test_valid_spdx_document_with_empty_gem_list
    sbom = generate_sbom([])
    errors = schema.validate(sbom.to_hash).to_a
    assert_empty errors, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n")
  end
end
