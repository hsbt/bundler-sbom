require "spec_helper"
require "bundler/lockfile_parser"
require "rexml/document"

RSpec.describe Bundler::Sbom::Generator do
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
      licenses: ["MIT"]
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

  describe "#generate" do
    context "with SPDX format (default)" do
      it "generates SBOM document" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [])
        )

        sbom = described_class.new.generate
        expect(sbom).to be_a(Bundler::Sbom::SPDX)
        expect(sbom.to_hash["SPDXID"]).to eq("SPDXRef-DOCUMENT")
        expect(sbom.to_hash["spdxVersion"]).to eq("SPDX-2.3")
        expect(sbom.to_hash["packages"]).to be_an(Array)
      end

      it "includes package information" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "rake", version: Gem::Version.new("13.0.6"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("rake", Gem::Version.new("13.0.6"))
          .and_return(rake_spec)

        sbom = described_class.new.generate
        package = sbom.to_hash["packages"].find { |p| p["name"] == "rake" }
        expect(package).not_to be_nil
        expect(package["name"]).to eq("rake")
        expect(package["versionInfo"]).to eq("13.0.6")
        expect(package["licenseDeclared"]).to eq("MIT")
      end

      it "handles multiple licenses from licenses array" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "bundler", version: Gem::Version.new("2.4.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("bundler", Gem::Version.new("2.4.0"))
          .and_return(multi_license_spec)

        sbom = described_class.new.generate
        package = sbom.to_hash["packages"].find { |p| p["name"] == "bundler" }
        expect(package).not_to be_nil
        expect(package["licenseDeclared"]).to eq("MIT, Apache-2.0")
      end

      it "sets NOASSERTION for packages with no license information" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "no-license", version: Gem::Version.new("1.0.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("no-license", Gem::Version.new("1.0.0"))
          .and_return(empty_license_spec)

        sbom = described_class.new.generate
        package = sbom.to_hash["packages"].find { |p| p["name"] == "no-license" }
        expect(package).not_to be_nil
        expect(package["licenseDeclared"]).to eq("NOASSERTION")
      end

      it "handles nil license information" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "nil-license", version: Gem::Version.new("1.0.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("nil-license", Gem::Version.new("1.0.0"))
          .and_return(nil_license_spec)

        sbom = described_class.new.generate
        package = sbom.to_hash["packages"].find { |p| p["name"] == "nil-license" }
        expect(package).not_to be_nil
        expect(package["licenseDeclared"]).to eq("NOASSERTION")
      end

      it "handles Gem::LoadError gracefully" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "missing-gem", version: Gem::Version.new("1.0.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("missing-gem", anything)
          .and_raise(Gem::LoadError)

        sbom = described_class.new.generate
        package = sbom.to_hash["packages"].find { |p| p["name"] == "missing-gem" }
        expect(package).not_to be_nil
        expect(package["licenseDeclared"]).to eq("NOASSERTION")
      end

      it "deduplicates gems with multiple platforms" do
        specs_with_duplicates = [
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "rake", version: Gem::Version.new("13.0.6"))
        ]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: specs_with_duplicates)
        )
        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new.generate
        expect(sbom.to_hash["packages"].size).to eq(2)
        expect(sbom.to_hash["documentDescribes"].size).to eq(2)

        herb_packages = sbom.to_hash["packages"].select { |p| p["name"] == "herb" }
        expect(herb_packages.size).to eq(1)

        rake_packages = sbom.to_hash["packages"].select { |p| p["name"] == "rake" }
        expect(rake_packages.size).to eq(1)
      end

      it "filters out excluded groups" do
        development_gem = double(name: "rspec", version: Gem::Version.new("3.12.0"))
        production_gem = double(name: "rails", version: Gem::Version.new("7.0.0"))

        all_specs = [production_gem, development_gem]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: all_specs)
        )

        definition = double
        allow(Bundler).to receive(:definition).and_return(definition)
        allow(definition).to receive(:groups).and_return([:default, :development])
        allow(definition).to receive(:dependencies_for).with(:default).and_return([
          double(name: "rails")
        ])
        allow(definition).to receive(:dependencies_for).with(:development).and_return([
          double(name: "rspec")
        ])

        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "spdx", without_groups: [:development]).generate
        expect(sbom.to_hash["packages"].size).to eq(1)
        expect(sbom.to_hash["packages"].first["name"]).to eq("rails")
      end

      it "includes transitive dependencies of included groups" do
        rails_gem = double(name: "rails", version: Gem::Version.new("7.0.0"))
        activesupport_gem = double(name: "activesupport", version: Gem::Version.new("7.0.0"))
        rspec_gem = double(name: "rspec", version: Gem::Version.new("3.12.0"))
        diff_lcs_gem = double(name: "diff-lcs", version: Gem::Version.new("1.5.0"))

        all_specs = [rails_gem, activesupport_gem, rspec_gem, diff_lcs_gem]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: all_specs)
        )

        definition = double
        allow(Bundler).to receive(:definition).and_return(definition)
        allow(definition).to receive(:groups).and_return([:default, :development])

        allow(definition).to receive(:dependencies_for).with(:default).and_return([
          double(name: "rails")
        ])
        allow(definition).to receive(:dependencies_for).with(:development).and_return([
          double(name: "rspec")
        ])

        allow(definition).to receive(:specs_for).with([:default]).and_return([
          rails_gem, activesupport_gem
        ])

        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "spdx", without_groups: [:development]).generate
        package_names = sbom.to_hash["packages"].map { |p| p["name"] }
        expect(package_names).to contain_exactly("rails", "activesupport")
      end

      it "excludes transitive dependencies of excluded groups" do
        rails_gem = double(name: "rails", version: Gem::Version.new("7.0.0"))
        rspec_gem = double(name: "rspec", version: Gem::Version.new("3.12.0"))
        diff_lcs_gem = double(name: "diff-lcs", version: Gem::Version.new("1.5.0"))

        all_specs = [rails_gem, rspec_gem, diff_lcs_gem]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: all_specs)
        )

        definition = double
        allow(Bundler).to receive(:definition).and_return(definition)
        allow(definition).to receive(:groups).and_return([:default, :development])

        allow(definition).to receive(:dependencies_for).with(:default).and_return([
          double(name: "rails")
        ])
        allow(definition).to receive(:dependencies_for).with(:development).and_return([
          double(name: "rspec")
        ])

        allow(definition).to receive(:specs_for).with([:default]).and_return([
          rails_gem
        ])

        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "spdx", without_groups: [:development]).generate
        package_names = sbom.to_hash["packages"].map { |p| p["name"] }
        expect(package_names).to contain_exactly("rails")
      end

      it "handles shared transitive dependencies correctly" do
        rails_gem = double(name: "rails", version: Gem::Version.new("7.0.0"))
        rspec_gem = double(name: "rspec", version: Gem::Version.new("3.12.0"))
        minitest_gem = double(name: "minitest", version: Gem::Version.new("5.18.0"))
        activesupport_gem = double(name: "activesupport", version: Gem::Version.new("7.0.0"))

        all_specs = [rails_gem, rspec_gem, minitest_gem, activesupport_gem]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: all_specs)
        )

        definition = double
        allow(Bundler).to receive(:definition).and_return(definition)
        allow(definition).to receive(:groups).and_return([:default, :development, :test])

        allow(definition).to receive(:dependencies_for).with(:default).and_return([
          double(name: "rails")
        ])
        allow(definition).to receive(:dependencies_for).with(:development).and_return([
          double(name: "rspec")
        ])
        allow(definition).to receive(:dependencies_for).with(:test).and_return([
          double(name: "minitest")
        ])

        allow(definition).to receive(:specs_for).with([:default, :test]).and_return([
          rails_gem, minitest_gem, activesupport_gem
        ])

        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "spdx", without_groups: [:development]).generate
        package_names = sbom.to_hash["packages"].map { |p| p["name"] }
        expect(package_names).to contain_exactly("rails", "minitest", "activesupport")
      end
    end

    context "with CycloneDX format" do
      it "generates CycloneDX SBOM document" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [])
        )
        sbom = described_class.new(format: "cyclonedx").generate
        expect(sbom).to be_a(Bundler::Sbom::CycloneDX)
        expect(sbom.to_hash["bomFormat"]).to eq("CycloneDX")
        expect(sbom.to_hash["specVersion"]).to eq("1.4")
        expect(sbom.to_hash["serialNumber"]).to match(/^urn:uuid:[0-9a-f-]+$/)
        expect(sbom.to_hash["components"]).to be_an(Array)
      end

      it "includes component information" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "rake", version: Gem::Version.new("13.0.6"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("rake", Gem::Version.new("13.0.6"))
          .and_return(rake_spec)
        sbom = described_class.new(format: "cyclonedx").generate
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
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "bundler", version: Gem::Version.new("2.4.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("bundler", Gem::Version.new("2.4.0"))
          .and_return(multi_license_spec)
        sbom = described_class.new(format: "cyclonedx").generate
        component = sbom.to_hash["components"].find { |c| c["name"] == "bundler" }
        expect(component).not_to be_nil
        expect(component["licenses"].size).to eq(2)
        license_ids = component["licenses"].map { |l| l["license"]["id"] }
        expect(license_ids).to include("MIT")
        expect(license_ids).to include("Apache-2.0")
      end

      it "omits licenses array for packages with no license information" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: [double(name: "no-license", version: Gem::Version.new("1.0.0"))])
        )
        allow(Gem::Specification).to receive(:find_by_name)
          .with("no-license", Gem::Version.new("1.0.0"))
          .and_return(empty_license_spec)
        sbom = described_class.new(format: "cyclonedx").generate
        component = sbom.to_hash["components"].find { |c| c["name"] == "no-license" }
        expect(component).not_to be_nil
        expect(component["licenses"]).to be_nil
      end

      it "includes metadata with timestamp and tools" do
        allow(Bundler::LockfileParser).to receive(:new).and_return(double(specs: []))
        sbom = described_class.new(format: "cyclonedx").generate
        expect(sbom.to_hash["metadata"]).to be_a(Hash)
        expect(sbom.to_hash["metadata"]["timestamp"]).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
        expect(sbom.to_hash["metadata"]["tools"]).to be_an(Array)
        expect(sbom.to_hash["metadata"]["tools"].first["name"]).to eq("bundle-sbom")
      end

      it "deduplicates gems with multiple platforms" do
        specs_with_duplicates = [
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "herb", version: Gem::Version.new("1.0.0")),
          double(name: "rake", version: Gem::Version.new("13.0.6"))
        ]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: specs_with_duplicates)
        )
        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "cyclonedx").generate
        expect(sbom.to_hash["components"].size).to eq(2)

        herb_components = sbom.to_hash["components"].select { |c| c["name"] == "herb" }
        expect(herb_components.size).to eq(1)

        rake_components = sbom.to_hash["components"].select { |c| c["name"] == "rake" }
        expect(rake_components.size).to eq(1)
      end

      it "filters out excluded groups" do
        development_gem = double(name: "rspec", version: Gem::Version.new("3.12.0"))
        production_gem = double(name: "rails", version: Gem::Version.new("7.0.0"))

        all_specs = [production_gem, development_gem]

        allow(Bundler::LockfileParser).to receive(:new).and_return(
          double(specs: all_specs)
        )

        definition = double
        allow(Bundler).to receive(:definition).and_return(definition)
        allow(definition).to receive(:groups).and_return([:default, :development])
        allow(definition).to receive(:dependencies_for).with(:default).and_return([
          double(name: "rails")
        ])
        allow(definition).to receive(:dependencies_for).with(:development).and_return([
          double(name: "rspec")
        ])

        allow(Gem::Specification).to receive(:find_by_name).and_return(nil)

        sbom = described_class.new(format: "cyclonedx", without_groups: [:development]).generate
        expect(sbom.to_hash["components"].size).to eq(1)
        expect(sbom.to_hash["components"].first["name"]).to eq("rails")
      end
    end

    context "when Gemfile.lock does not exist" do
      before do
        FileUtils.rm("Gemfile.lock") if File.exist?("Gemfile.lock")
        mock_lockfile = instance_double(Pathname, exist?: false)
        allow(Bundler).to receive(:default_lockfile).and_return(mock_lockfile)
      end

      it "raises error with message" do
        expect(Bundler.ui).to receive(:error).with("No Gemfile.lock found. Run `bundle install` first.")
        expect {
          described_class.new.generate
        }.to raise_error(Bundler::Sbom::GemfileLockNotFoundError, "No Gemfile.lock found")
      end
    end
  end

  describe "#to_xml" do
    context "with SPDX format" do
      let(:sbom_hash) do
        {
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
                  "referenceCategory" => "PACKAGE_MANAGER",
                  "referenceType" => "purl",
                  "referenceLocator" => "pkg:gem/rake@13.0.6"
                }
              ]
            }
          ]
        }
      end

      it "converts SBOM instance to XML format" do
        sbom = Bundler::Sbom::SPDX.new(sbom_hash)
        xml_content = sbom.to_xml
        expect(xml_content).to be_a(String)
        expect(xml_content).to include('<?xml version="1.0" encoding="UTF-8"?>')

        doc = REXML::Document.new(xml_content)
        root = doc.root

        expect(root.name).to eq("SpdxDocument")
        expect(REXML::XPath.first(root, "SPDXID").text).to eq("SPDXRef-DOCUMENT")
        expect(REXML::XPath.first(root, "spdxVersion").text).to eq("SPDX-2.3")
        expect(REXML::XPath.first(root, "name").text).to eq("test-project")

        package = REXML::XPath.first(root, "package")
        expect(package).not_to be_nil
        expect(REXML::XPath.first(package, "name").text).to eq("rake")
        expect(REXML::XPath.first(package, "versionInfo").text).to eq("13.0.6")
        expect(REXML::XPath.first(package, "licenseDeclared").text).to eq("MIT")

        ext_ref = REXML::XPath.first(package, "externalRef")
        expect(ext_ref).not_to be_nil
        expect(REXML::XPath.first(ext_ref, "referenceLocator").text).to eq("pkg:gem/rake@13.0.6")
      end
    end

    context "with CycloneDX format" do
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
        sbom = Bundler::Sbom::CycloneDX.new(cyclonedx_hash)
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
  end

  describe ".parse_xml" do
    context "with SPDX format" do
      let(:xml_content) do
        <<~XML
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
                <referenceCategory>PACKAGE_MANAGER</referenceCategory>
                <referenceType>purl</referenceType>
                <referenceLocator>pkg:gem/rake@13.0.6</referenceLocator>
              </externalRef>
            </package>
          </SpdxDocument>
        XML
      end

      it "parses XML content into SBOM instance" do
        sbom = described_class.parse_xml(xml_content)

        expect(sbom).to be_a(Bundler::Sbom::SPDX)
        expect(sbom.to_hash["SPDXID"]).to eq("SPDXRef-DOCUMENT")
        expect(sbom.to_hash["spdxVersion"]).to eq("SPDX-2.3")
        expect(sbom.to_hash["name"]).to eq("test-project")
        expect(sbom.to_hash["dataLicense"]).to eq("CC0-1.0")

        expect(sbom.to_hash["creationInfo"]).to be_a(Hash)
        expect(sbom.to_hash["creationInfo"]["created"]).to eq("2023-01-01T12:00:00Z")
        expect(sbom.to_hash["creationInfo"]["creators"]).to include("Tool: bundle-sbom")

        expect(sbom.to_hash["packages"]).to be_an(Array)
        expect(sbom.to_hash["packages"].size).to eq(1)

        package = sbom.to_hash["packages"].first
        expect(package["SPDXID"]).to eq("SPDXRef-Package-rake")
        expect(package["name"]).to eq("rake")
        expect(package["versionInfo"]).to eq("13.0.6")
        expect(package["licenseDeclared"]).to eq("MIT")

        expect(package["externalRefs"]).to be_an(Array)
        expect(package["externalRefs"].size).to eq(1)

        ext_ref = package["externalRefs"].first
        expect(ext_ref["referenceCategory"]).to eq("PACKAGE_MANAGER")
        expect(ext_ref["referenceType"]).to eq("purl")
        expect(ext_ref["referenceLocator"]).to eq("pkg:gem/rake@13.0.6")
      end
    end

    context "with CycloneDX format" do
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

      it "parses CycloneDX XML content and returns CycloneDX instance" do
        sbom = described_class.parse_xml(cyclonedx_xml_content)

        expect(sbom).to be_a(Bundler::Sbom::CycloneDX)
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

    it "handles malformed XML gracefully" do
      malformed_xml = "<invalid>XML Content"
      expect { described_class.parse_xml(malformed_xml) }.to raise_error(REXML::ParseException)
    end
  end

  describe ".from_hash" do
    it "returns SPDX instance for SPDX hash" do
      sbom = described_class.from_hash({"SPDXID" => "SPDXRef-DOCUMENT", "packages" => []})
      expect(sbom).to be_a(Bundler::Sbom::SPDX)
    end

    it "returns CycloneDX instance for CycloneDX hash" do
      sbom = described_class.from_hash({"bomFormat" => "CycloneDX", "components" => []})
      expect(sbom).to be_a(Bundler::Sbom::CycloneDX)
    end
  end
end
