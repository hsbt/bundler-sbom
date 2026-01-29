require "bundler"
require "securerandom"
require "rexml/document"

module Bundler
  module Sbom
    class CycloneDX
      def self.generate(lockfile, document_name)
        serial_number = SecureRandom.uuid
        timestamp = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        sbom = {
          "bomFormat" => "CycloneDX",
          "specVersion" => "1.4",
          "serialNumber" => "urn:uuid:#{serial_number}",
          "version" => 1,
          "metadata" => {
            "timestamp" => timestamp,
            "tools" => [
              {
                "vendor" => "Bundler",
                "name" => "bundle-sbom",
                "version" => Bundler::Sbom::VERSION
              }
            ],
            "component" => {
              "type" => "application",
              "name" => document_name,
              "version" => "0.0.0" # Default version
            }
          },
          "components" => []
        }

        # Deduplicate specs by name and version
        seen_gems = Set.new
        lockfile.specs.each do |spec|
          gem_key = "#{spec.name}:#{spec.version}"
          next if seen_gems.include?(gem_key)
          seen_gems.add(gem_key)
          begin
            gemspec = Gem::Specification.find_by_name(spec.name, spec.version)
            licenses = []
            if gemspec
              if gemspec.license && !gemspec.license.empty?
                licenses << gemspec.license
              end
              if gemspec.licenses && !gemspec.licenses.empty?
                licenses.concat(gemspec.licenses)
              end
              licenses.uniq!
            end
          rescue Gem::LoadError
            licenses = []
          end

          component = {
            "type" => "library",
            "name" => spec.name,
            "version" => spec.version.to_s,
            "purl" => "pkg:gem/#{spec.name}@#{spec.version}"
          }

          unless licenses.empty?
            component["licenses"] = licenses.map { |license| {"license" => {"id" => license}} }
          end

          sbom["components"] << component
        end

        sbom
      end

      def self.to_xml(sbom)
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new("1.0", "UTF-8")

        # Root element
        root = REXML::Element.new("bom")
        root.add_namespace("http://cyclonedx.org/schema/bom/1.4")
        root.add_attributes({
          "serialNumber" => sbom["serialNumber"],
          "version" => sbom["version"].to_s
        })
        doc.add_element(root)

        # Metadata
        metadata = REXML::Element.new("metadata")
        root.add_element(metadata)

        add_element(metadata, "timestamp", sbom["metadata"]["timestamp"])

        # Tools
        tools = REXML::Element.new("tools")
        metadata.add_element(tools)

        sbom["metadata"]["tools"].each do |tool_data|
          tool = REXML::Element.new("tool")
          tools.add_element(tool)

          add_element(tool, "vendor", tool_data["vendor"])
          add_element(tool, "name", tool_data["name"])
          add_element(tool, "version", tool_data["version"].to_s)
        end

        # Component (root project)
        component = REXML::Element.new("component")
        component.add_attribute("type", sbom["metadata"]["component"]["type"])
        metadata.add_element(component)

        add_element(component, "name", sbom["metadata"]["component"]["name"])
        add_element(component, "version", sbom["metadata"]["component"]["version"])

        # Components
        components = REXML::Element.new("components")
        root.add_element(components)

        sbom["components"].each do |comp_data|
          comp = REXML::Element.new("component")
          comp.add_attribute("type", comp_data["type"])
          components.add_element(comp)

          add_element(comp, "name", comp_data["name"])
          add_element(comp, "version", comp_data["version"])
          add_element(comp, "purl", comp_data["purl"])

          # Licenses
          if comp_data["licenses"] && !comp_data["licenses"].empty?
            licenses = REXML::Element.new("licenses")
            comp.add_element(licenses)

            comp_data["licenses"].each do |license_data|
              license = REXML::Element.new("license")
              licenses.add_element(license)

              if license_data["license"]["id"]
                add_element(license, "id", license_data["license"]["id"])
              end
            end
          end
        end

        formatter = REXML::Formatters::Pretty.new(2)
        formatter.compact = true
        output = ""
        formatter.write(doc, output)
        output.sub(%r{<\?xml version='1\.0' encoding='UTF-8'\?>}, '<?xml version="1.0" encoding="UTF-8"?>')
      end

      def self.parse_xml(doc)
        root = doc.root

        sbom = {
          "bomFormat" => "CycloneDX",
          "specVersion" => "1.4",
          "serialNumber" => root.attributes["serialNumber"],
          "version" => root.attributes["version"].to_i,
          "metadata" => {
            "timestamp" => get_element_text(root, "metadata/timestamp"),
            "tools" => [],
            "component" => {
              "type" => REXML::XPath.first(root, "metadata/component").attributes["type"],
              "name" => get_element_text(root, "metadata/component/name"),
              "version" => get_element_text(root, "metadata/component/version")
            }
          },
          "components" => []
        }

        # Collect tools
        REXML::XPath.each(root, "metadata/tools/tool") do |tool|
          tool_data = {
            "vendor" => get_element_text(tool, "vendor"),
            "name" => get_element_text(tool, "name"),
            "version" => get_element_text(tool, "version")
          }
          sbom["metadata"]["tools"] << tool_data
        end

        # Collect components
        REXML::XPath.each(root, "components/component") do |comp|
          component = {
            "type" => comp.attributes["type"],
            "name" => get_element_text(comp, "name"),
            "version" => get_element_text(comp, "version"),
            "purl" => get_element_text(comp, "purl")
          }

          # Collect licenses
          licenses = []
          REXML::XPath.each(comp, "licenses/license") do |license|
            license_id = get_element_text(license, "id")
            licenses << {"license" => {"id" => license_id}} if license_id
          end

          component["licenses"] = licenses unless licenses.empty?
          sbom["components"] << component
        end

        # Convert CycloneDX format to SPDX-like format for compatibility with Reporter
        {
          "packages" => sbom["components"].map do |comp|
            license_string = if comp["licenses"]
              comp["licenses"].map { |l| l["license"]["id"] }.join(", ")
            else
              "NOASSERTION"
            end
            {
              "name" => comp["name"],
              "versionInfo" => comp["version"],
              "licenseDeclared" => license_string
            }
          end
        }
      end

      def self.to_report_format(sbom)
        {
          "packages" => sbom["components"].map do |comp|
            license_string = if comp["licenses"]
              comp["licenses"].map { |l| l["license"]["id"] }.join(", ")
            else
              "NOASSERTION"
            end
            {
              "name" => comp["name"],
              "versionInfo" => comp["version"],
              "licenseDeclared" => license_string
            }
          end
        }
      end

      private

      def self.add_element(parent, name, value)
        element = REXML::Element.new(name)
        element.text = value
        parent.add_element(element)
      end

      def self.get_element_text(element, xpath)
        result = REXML::XPath.first(element, xpath)
        result ? result.text : nil
      end
    end
  end
end
