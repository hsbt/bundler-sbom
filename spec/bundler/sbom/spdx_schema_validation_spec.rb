require "spec_helper"
require "json_schemer"

RSpec.describe "SPDX 2.3 JSON Schema validation" do
  let(:schema) do
    schema_path = File.join(SpecHelper.root, "spec", "fixtures", "spdx-schema.json")
    JSONSchemer.schema(Pathname.new(schema_path))
  end

  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      Dir.chdir(dir) do
        example.run
      end
    end
  end

  def generate_sbom(gem_data)
    Bundler::Sbom::SPDX.generate(gem_data, "test-project")
  end

  it "produces a valid SPDX 2.3 document with a single gem" do
    sbom = generate_sbom([{name: "rake", version: "13.0.6", licenses: ["MIT"]}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n") }
  end

  it "produces a valid SPDX 2.3 document with multiple gems" do
    gem_data = [
      {name: "rake", version: "13.0.6", licenses: ["MIT"]},
      {name: "rspec", version: "3.12.0", licenses: ["MIT"]},
      {name: "rails", version: "7.0.0", licenses: ["MIT", "Apache-2.0"]}
    ]
    sbom = generate_sbom(gem_data)
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n") }
  end

  it "produces a valid SPDX 2.3 document with no license information" do
    sbom = generate_sbom([{name: "unknown-gem", version: "1.0.0", licenses: []}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n") }
  end

  it "produces a valid SPDX 2.3 document with non-SPDX license IDs" do
    sbom = generate_sbom([{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n") }
  end

  it "produces a valid SPDX 2.3 document with empty gem list" do
    sbom = generate_sbom([])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]}" }.join("\n") }
  end
end
