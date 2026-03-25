require "spec_helper"
require "json_schemer"

RSpec.describe "CycloneDX 1.4 JSON Schema validation" do
  let(:schema) do
    fixtures_dir = File.join(SpecHelper.root, "spec", "fixtures")
    schema_path = File.join(fixtures_dir, "bom-1.4.schema.json")
    ref_resolver = proc do |uri|
      filename = uri.path.split("/").last
      # Map CycloneDX schema file references
      local_files = {
        "spdx.schema.json" => "spdx.SPDX.schema.json"
      }
      local_name = local_files[filename] || filename
      file = File.join(fixtures_dir, local_name)
      JSON.parse(File.read(file)) if File.exist?(file)
    end
    JSONSchemer.schema(Pathname.new(schema_path), ref_resolver: ref_resolver)
  end

  around(:each) do |example|
    SpecHelper.with_temp_dir do |dir|
      Dir.chdir(dir) do
        example.run
      end
    end
  end

  def generate_sbom(gem_data)
    Bundler::Sbom::CycloneDX.generate(gem_data, "test-project")
  end

  it "produces a valid CycloneDX 1.4 document with a single gem" do
    sbom = generate_sbom([{name: "rake", version: "13.0.6", licenses: ["MIT"]}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} - #{e["details"]}" }.join("\n") }
  end

  it "produces a valid CycloneDX 1.4 document with multiple gems" do
    gem_data = [
      {name: "rake", version: "13.0.6", licenses: ["MIT"]},
      {name: "rspec", version: "3.12.0", licenses: ["MIT"]},
      {name: "rails", version: "7.0.0", licenses: ["MIT", "Apache-2.0"]}
    ]
    sbom = generate_sbom(gem_data)
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} - #{e["details"]}" }.join("\n") }
  end

  it "produces a valid CycloneDX 1.4 document with no license information" do
    sbom = generate_sbom([{name: "unknown-gem", version: "1.0.0", licenses: []}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} - #{e["details"]}" }.join("\n") }
  end

  it "produces a valid CycloneDX 1.4 document with non-SPDX license IDs" do
    sbom = generate_sbom([{name: "my-gem", version: "1.0.0", licenses: ["Nonstandard"]}])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} - #{e["details"]}" }.join("\n") }
  end

  it "produces a valid CycloneDX 1.4 document with empty gem list" do
    sbom = generate_sbom([])
    errors = schema.validate(sbom.to_hash).to_a
    expect(errors).to be_empty, -> { errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} - #{e["details"]}" }.join("\n") }
  end
end
