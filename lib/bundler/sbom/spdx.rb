require "bundler"
require "securerandom"
require "bundler/sbom/sbom_document"

module Bundler
  module Sbom
    class SPDX
      include SbomDocument

      def self.generate(gem_data, document_name)
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

        gem_data.each do |gem|
          license_string = gem[:licenses].empty? ? "NOASSERTION" : gem[:licenses].join(", ")

          package = {
            "SPDXID" => "SPDXRef-Package-#{gem[:name]}",
            "name" => gem[:name],
            "versionInfo" => gem[:version],
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
                "referenceLocator" => "pkg:gem/#{gem[:name]}@#{gem[:version]}"
              }
            ]
          }
          sbom["packages"] << package
        end

        sbom["documentDescribes"] = sbom["packages"].map { |p| p["SPDXID"] }
        new(sbom)
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

        REXML::XPath.each(root, "creationInfo/creator") do |creator|
          sbom["creationInfo"]["creators"] << creator.text
        end

        REXML::XPath.each(root, "documentDescribes") do |describes|
          sbom["documentDescribes"] << describes.text
        end

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

        new(sbom)
      end

      def to_xml
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new("1.0", "UTF-8")

        root = REXML::Element.new("SpdxDocument")
        root.add_namespace("https://spdx.org/spdxdocs/")
        doc.add_element(root)

        add_element(root, "SPDXID", @data["SPDXID"])
        add_element(root, "spdxVersion", @data["spdxVersion"])
        add_element(root, "name", @data["name"])
        add_element(root, "dataLicense", @data["dataLicense"])
        add_element(root, "documentNamespace", @data["documentNamespace"])

        creation_info = REXML::Element.new("creationInfo")
        root.add_element(creation_info)
        add_element(creation_info, "created", @data["creationInfo"]["created"])
        add_element(creation_info, "licenseListVersion", @data["creationInfo"]["licenseListVersion"])

        @data["creationInfo"]["creators"].each do |creator|
          add_element(creation_info, "creator", creator)
        end

        @data["documentDescribes"].each do |describes|
          add_element(root, "documentDescribes", describes)
        end

        @data["packages"].each do |pkg|
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

        format_xml(doc)
      end

      def to_report_format
        {
          "packages" => @data["packages"].map do |pkg|
            {
              "name" => pkg["name"],
              "versionInfo" => pkg["versionInfo"],
              "licenseDeclared" => pkg["licenseDeclared"]
            }
          end
        }
      end
    end
  end
end
