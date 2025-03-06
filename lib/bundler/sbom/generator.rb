require "bundler"
require "securerandom"
require "json"
require "rexml/document"

module Bundler
  module Sbom
    class GemfileLockNotFoundError < StandardError; end

    class Generator
      def self.generate_sbom(format = "spdx")
        lockfile_path = Bundler.default_lockfile
        if !lockfile_path || !lockfile_path.exist?
          Bundler.ui.error "No Gemfile.lock found. Run `bundle install` first."
          raise GemfileLockNotFoundError, "No Gemfile.lock found"
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)

        case format.to_s.downcase
        when "cyclonedx"
          generate_cyclonedx(lockfile, document_name)
        else # default to spdx
          generate_spdx(lockfile, document_name)
        end
      end

      def self.generate_spdx(lockfile, document_name)
        spdx_id = SecureRandom.uuid

        sbom = {
          "SPDXID" => "SPDXRef-DOCUMENT",
          "spdxVersion" => "SPDX-2.3",
          "creationInfo" => {
            "created" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators" => ["Tool: bundle-sbom"],
            "licenseListVersion" => "3.20"
          },
          "name" => document_name,
          "dataLicense" => "CC0-1.0",
          "documentNamespace" => "https://spdx.org/spdxdocs/#{document_name}-#{spdx_id}",
          "packages" => []
        }

        lockfile.specs.each do |spec|
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

            license_string = licenses.empty? ? "NOASSERTION" : licenses.join(", ")
          rescue Gem::LoadError
            license_string = "NOASSERTION"
          end

          package = {
            "SPDXID" => "SPDXRef-Package-#{spec.name}",
            "name" => spec.name,
            "versionInfo" => spec.version.to_s,
            "downloadLocation" => "NOASSERTION",
            "filesAnalyzed" => false,
            "licenseConcluded" => license_string,
            "licenseDeclared" => license_string,
            "copyrightText" => "NOASSERTION",
            "supplier" => "NOASSERTION",
            "externalRefs" => [
              {
                "referenceCategory" => "PACKAGE_MANAGER",
                "referenceType" => "purl",
                "referenceLocator" => "pkg:gem/#{spec.name}@#{spec.version}"
              }
            ]
          }
          sbom["packages"] << package
        end

        sbom["documentDescribes"] = sbom["packages"].map { |p| p["SPDXID"] }
        sbom
      end

      def self.generate_cyclonedx(lockfile, document_name)
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

        lockfile.specs.each do |spec|
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
            component["licenses"] = licenses.map { |license| { "license" => { "id" => license } } }
          end

          sbom["components"] << component
        end

        sbom
      end

      def self.convert_to_xml(sbom)
        if sbom["bomFormat"] == "CycloneDX"
          convert_cyclonedx_to_xml(sbom)
        else
          convert_spdx_to_xml(sbom)
        end
      end

      def self.convert_spdx_to_xml(sbom)
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new("1.0", "UTF-8")
        
        # Root element
        root = REXML::Element.new("SpdxDocument")
        root.add_namespace("https://spdx.org/spdxdocs/")
        doc.add_element(root)
        
        # Document info
        add_element(root, "SPDXID", sbom["SPDXID"])
        add_element(root, "spdxVersion", sbom["spdxVersion"])
        add_element(root, "name", sbom["name"])
        add_element(root, "dataLicense", sbom["dataLicense"])
        add_element(root, "documentNamespace", sbom["documentNamespace"])
        
        # Creation info
        creation_info = REXML::Element.new("creationInfo")
        root.add_element(creation_info)
        add_element(creation_info, "created", sbom["creationInfo"]["created"])
        add_element(creation_info, "licenseListVersion", sbom["creationInfo"]["licenseListVersion"])
        
        sbom["creationInfo"]["creators"].each do |creator|
          add_element(creation_info, "creator", creator)
        end
        
        # Describes
        sbom["documentDescribes"].each do |describes|
          add_element(root, "documentDescribes", describes)
        end
        
        # Packages
        sbom["packages"].each do |pkg|
          package = REXML::Element.new("package")
          root.add_element(package)
          
          add_element(package, "SPDXID", pkg["SPDXID"])
          add_element(package, "name", pkg["name"])
          add_element(package, "versionInfo", pkg["versionInfo"])
          add_element(package, "downloadLocation", pkg["downloadLocation"])
          add_element(package, "filesAnalyzed", pkg["filesAnalyzed"].to_s)
          add_element(package, "licenseConcluded", pkg["licenseConcluded"])
          add_element(package, "licenseDeclared", pkg["licenseDeclared"])
          add_element(package, "copyrightText", pkg["copyrightText"])
          add_element(package, "supplier", pkg["supplier"])
          
          # External references
          if pkg["externalRefs"]
            pkg["externalRefs"].each do |ref|
              ext_ref = REXML::Element.new("externalRef")
              package.add_element(ext_ref)
              
              add_element(ext_ref, "referenceCategory", ref["referenceCategory"])
              add_element(ext_ref, "referenceType", ref["referenceType"])
              add_element(ext_ref, "referenceLocator", ref["referenceLocator"])
            end
          end
        end
        
        formatter = REXML::Formatters::Pretty.new(2)
        formatter.compact = true
        output = ""
        formatter.write(doc, output)
        output.sub(%r{<\?xml version='1\.0' encoding='UTF-8'\?>}, '<?xml version="1.0" encoding="UTF-8"?>')
      end

      def self.convert_cyclonedx_to_xml(sbom)
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new("1.0", "UTF-8")
        
        # Root element
        root = REXML::Element.new("bom")
        root.add_namespace("http://cyclonedx.org/schema/bom/1.4")
        root.add_attributes({
          "serialNumber" => sbom["serialNumber"],
          "version" => sbom["version"].to_s,
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
      
      def self.parse_xml(xml_content)
        doc = REXML::Document.new(xml_content)
        root = doc.root
        
        # Determine if it's CycloneDX or SPDX
        if root.name == "bom" && root.namespace.include?("cyclonedx.org")
          parse_cyclonedx_xml(doc)
        else
          parse_spdx_xml(doc)
        end
      end

      def self.parse_spdx_xml(doc)
        root = doc.root
        
        sbom = {
          "SPDXID" => get_element_text(root, "SPDXID"),
          "spdxVersion" => get_element_text(root, "spdxVersion"),
          "name" => get_element_text(root, "name"),
          "dataLicense" => get_element_text(root, "dataLicense"),
          "documentNamespace" => get_element_text(root, "documentNamespace"),
          "creationInfo" => {
            "created" => get_element_text(root, "creationInfo/created"),
            "licenseListVersion" => get_element_text(root, "creationInfo/licenseListVersion"),
            "creators" => []
          },
          "packages" => [],
          "documentDescribes" => []
        }
        
        # Collect creators
        REXML::XPath.each(root, "creationInfo/creator") do |creator|
          sbom["creationInfo"]["creators"] << creator.text
        end
        
        # Collect documentDescribes
        REXML::XPath.each(root, "documentDescribes") do |describes|
          sbom["documentDescribes"] << describes.text
        end
        
        # Collect packages
        REXML::XPath.each(root, "package") do |pkg_element|
          package = {
            "SPDXID" => get_element_text(pkg_element, "SPDXID"),
            "name" => get_element_text(pkg_element, "name"),
            "versionInfo" => get_element_text(pkg_element, "versionInfo"),
            "downloadLocation" => get_element_text(pkg_element, "downloadLocation"),
            "filesAnalyzed" => get_element_text(pkg_element, "filesAnalyzed") == "true",
            "licenseConcluded" => get_element_text(pkg_element, "licenseConcluded"),
            "licenseDeclared" => get_element_text(pkg_element, "licenseDeclared"),
            "copyrightText" => get_element_text(pkg_element, "copyrightText"),
            "supplier" => get_element_text(pkg_element, "supplier"),
            "externalRefs" => []
          }
          
          # Collect external references
          REXML::XPath.each(pkg_element, "externalRef") do |ref_element|
            ref = {
              "referenceCategory" => get_element_text(ref_element, "referenceCategory"),
              "referenceType" => get_element_text(ref_element, "referenceType"),
              "referenceLocator" => get_element_text(ref_element, "referenceLocator")
            }
            package["externalRefs"] << ref
          end
          
          sbom["packages"] << package
        end
        
        sbom
      end

      def self.parse_cyclonedx_xml(doc)
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
            licenses << { "license" => { "id" => license_id } } if license_id
          end
          
          component["licenses"] = licenses unless licenses.empty?
          sbom["components"] << component
        end
        
        # Convert CycloneDX format to SPDX-like format for compatibility with Reporter
        converted_sbom = {
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
        
        converted_sbom
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