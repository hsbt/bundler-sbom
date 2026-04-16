require "bundler"
require "securerandom"
require "bundler/sbom/sbom_document"

module Bundler
  module Sbom
    class CycloneDX
      include SbomDocument

      SPEC_VERSION = "1.7"
      XML_NAMESPACE = "http://cyclonedx.org/schema/bom/#{SPEC_VERSION}"

      def self.generate(gem_data, document_name, direct_dependencies: [])
        serial_number = SecureRandom.uuid
        timestamp = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        root_ref = document_name
        sbom = {
          "bomFormat" => "CycloneDX",
          "specVersion" => SPEC_VERSION,
          "serialNumber" => "urn:uuid:#{serial_number}",
          "version" => 1,
          "metadata" => {
            "timestamp" => timestamp,
            "tools" => {
              "components" => [
                {
                  "type" => "application",
                  "name" => "bundle-sbom",
                  "version" => Bundler::Sbom::VERSION
                }
              ]
            },
            "component" => {
              "type" => "application",
              "bom-ref" => root_ref,
              "name" => document_name,
              "version" => "0.0.0"
            }
          },
          "components" => [],
          "dependencies" => []
        }

        ref_by_name = {}
        gem_data.each do |gem|
          ref_by_name[gem[:name]] = "pkg:gem/#{gem[:name]}@#{gem[:version]}"
        end

        gem_data.each do |gem|
          purl = ref_by_name[gem[:name]]
          component = {
            "type" => "library",
            "bom-ref" => purl,
            "name" => gem[:name],
            "version" => gem[:version],
            "purl" => purl
          }

          unless gem[:licenses].empty?
            component["licenses"] = gem[:licenses].map { |license| build_license_entry(license) }
          end

          sbom["components"] << component

          dep_refs = (gem[:dependencies] || []).filter_map { |name| ref_by_name[name] }
          sbom["dependencies"] << {"ref" => purl, "dependsOn" => dep_refs}
        end

        root_deps = direct_dependencies.filter_map { |name| ref_by_name[name] }
        sbom["dependencies"].unshift({"ref" => root_ref, "dependsOn" => root_deps})

        new(sbom)
      end

      def self.parse_xml(doc)
        root = doc.root
        spec_version = root.namespace.to_s[%r{/bom/(\d+\.\d+)}, 1] || SPEC_VERSION

        sbom = {
          "bomFormat" => "CycloneDX",
          "specVersion" => spec_version,
          "serialNumber" => root.attributes["serialNumber"],
          "version" => root.attributes["version"].to_i,
          "metadata" => {
            "timestamp" => get_element_text(root, "metadata/timestamp"),
            "tools" => {"components" => []},
            "component" => {
              "type" => REXML::XPath.first(root, "metadata/component").attributes["type"],
              "name" => get_element_text(root, "metadata/component/name"),
              "version" => get_element_text(root, "metadata/component/version")
            }
          },
          "components" => []
        }

        REXML::XPath.each(root, "metadata/tools/components/component") do |tool|
          sbom["metadata"]["tools"]["components"] << {
            "type" => tool.attributes["type"],
            "name" => get_element_text(tool, "name"),
            "version" => get_element_text(tool, "version")
          }
        end

        REXML::XPath.each(root, "metadata/tools/tool") do |tool|
          sbom["metadata"]["tools"]["components"] << {
            "type" => "application",
            "name" => get_element_text(tool, "name"),
            "version" => get_element_text(tool, "version")
          }
        end

        REXML::XPath.each(root, "components/component") do |comp|
          component = {
            "type" => comp.attributes["type"],
            "bom-ref" => comp.attributes["bom-ref"],
            "name" => get_element_text(comp, "name"),
            "version" => get_element_text(comp, "version"),
            "purl" => get_element_text(comp, "purl")
          }.compact

          licenses = []
          REXML::XPath.each(comp, "licenses/license") do |license|
            license_id = get_element_text(license, "id")
            license_name = get_element_text(license, "name")
            if license_id
              licenses << {"license" => {"id" => license_id}}
            elsif license_name
              licenses << {"license" => {"name" => license_name}}
            end
          end

          component["licenses"] = licenses unless licenses.empty?
          sbom["components"] << component
        end

        meta_component = REXML::XPath.first(root, "metadata/component")
        if meta_component && meta_component.attributes["bom-ref"]
          sbom["metadata"]["component"]["bom-ref"] = meta_component.attributes["bom-ref"]
        end

        sbom["dependencies"] = []
        REXML::XPath.each(root, "dependencies/dependency") do |dep|
          depends_on = REXML::XPath.each(dep, "dependency").map { |c| c.attributes["ref"] }
          sbom["dependencies"] << {"ref" => dep.attributes["ref"], "dependsOn" => depends_on}
        end

        new(sbom)
      end

      def to_xml
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new("1.0", "UTF-8")

        root = REXML::Element.new("bom")
        root.add_namespace(XML_NAMESPACE)
        root.add_attributes({
          "serialNumber" => @data["serialNumber"],
          "version" => @data["version"].to_s
        })
        doc.add_element(root)

        metadata = REXML::Element.new("metadata")
        root.add_element(metadata)

        add_element(metadata, "timestamp", @data["metadata"]["timestamp"])

        tools = REXML::Element.new("tools")
        metadata.add_element(tools)

        tool_components = REXML::Element.new("components")
        tools.add_element(tool_components)

        each_tool_component do |tool_data|
          tool = REXML::Element.new("component")
          tool.add_attribute("type", tool_data["type"] || "application")
          tool_components.add_element(tool)

          add_element(tool, "name", tool_data["name"])
          add_element(tool, "version", tool_data["version"].to_s)
        end

        component = REXML::Element.new("component")
        component.add_attribute("type", @data["metadata"]["component"]["type"])
        if @data["metadata"]["component"]["bom-ref"]
          component.add_attribute("bom-ref", @data["metadata"]["component"]["bom-ref"])
        end
        metadata.add_element(component)

        add_element(component, "name", @data["metadata"]["component"]["name"])
        add_element(component, "version", @data["metadata"]["component"]["version"])

        components = REXML::Element.new("components")
        root.add_element(components)

        @data["components"].each do |comp_data|
          comp = REXML::Element.new("component")
          comp.add_attribute("type", comp_data["type"])
          comp.add_attribute("bom-ref", comp_data["bom-ref"]) if comp_data["bom-ref"]
          components.add_element(comp)

          add_element(comp, "name", comp_data["name"])
          add_element(comp, "version", comp_data["version"])
          add_element(comp, "purl", comp_data["purl"])

          if comp_data["licenses"] && !comp_data["licenses"].empty?
            licenses = REXML::Element.new("licenses")
            comp.add_element(licenses)

            comp_data["licenses"].each do |license_data|
              license = REXML::Element.new("license")
              licenses.add_element(license)

              if license_data["license"]["id"]
                add_element(license, "id", license_data["license"]["id"])
              elsif license_data["license"]["name"]
                add_element(license, "name", license_data["license"]["name"])
              end
            end
          end
        end

        if @data["dependencies"] && !@data["dependencies"].empty?
          deps_el = REXML::Element.new("dependencies")
          root.add_element(deps_el)

          @data["dependencies"].each do |dep|
            dep_el = REXML::Element.new("dependency")
            dep_el.add_attribute("ref", dep["ref"])
            deps_el.add_element(dep_el)

            (dep["dependsOn"] || []).each do |child_ref|
              child = REXML::Element.new("dependency")
              child.add_attribute("ref", child_ref)
              dep_el.add_element(child)
            end
          end
        end

        format_xml(doc)
      end

      def to_report_format
        {
          "packages" => @data["components"].map do |comp|
            license_string = if comp["licenses"]
              comp["licenses"].map { |l| l["license"]["id"] || l["license"]["name"] }.join(", ")
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

      def each_tool_component(&block)
        tools = @data.dig("metadata", "tools")
        case tools
        when Hash
          (tools["components"] || []).each(&block)
        when Array
          tools.each(&block)
        end
      end

      def self.build_license_entry(license)
        mapped = SPDX::DEPRECATED_LICENSE_MAP[license]
        license = mapped if mapped

        if SpdxLicenses.exist?(license)
          {"license" => {"id" => license}}
        else
          {"license" => {"name" => license}}
        end
      end
      private_class_method :build_license_entry
    end
  end
end
