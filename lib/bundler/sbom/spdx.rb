require "bundler"
require "securerandom"
require "rexml/document"

module Bundler
  module Sbom
    class SPDX
      def self.generate(lockfile, document_name)
        spdx_id = generate_spdx_id
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

      def self.to_xml(sbom)
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

      def self.parse_xml(doc)
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

      def self.to_report_format(sbom)
        # SPDXフォーマットは既にレポート形式と互換性があるため、
        # packagesセクションだけを抽出して返す
        {
          "packages" => sbom["packages"].map do |pkg|
            {
              "name" => pkg["name"],
              "versionInfo" => pkg["versionInfo"],
              "licenseDeclared" => pkg["licenseDeclared"]
            }
          end
        }
      end

      def self.generate_spdx_id
        SecureRandom.uuid
      end

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
