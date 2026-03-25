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
          spdx_licenses = gem[:licenses].map { |l| normalize_license_id(l) }
          license_string = spdx_licenses.empty? ? "NOASSERTION" : spdx_licenses.join(" AND ")

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
                "referenceCategory" => "PACKAGE-MANAGER",
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

      KNOWN_SPDX_IDS = %w[
        0BSD AAL AFL-3.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0-only AGPL-3.0-or-later
        Apache-1.0 Apache-1.1 Apache-2.0 APSL-1.0 APSL-1.1 APSL-2.0
        Artistic-1.0 Artistic-2.0
        Beerware BlueOak-1.0.0 BSL-1.0
        BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-3-Clause-LBNL
        CAL-1.0 CAL-1.0-Combined-Work-Exception
        CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-3.0 CC-BY-4.0
        CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5 CC-BY-NC-3.0 CC-BY-NC-4.0
        CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5 CC-BY-NC-ND-3.0 CC-BY-NC-ND-4.0
        CC-BY-NC-SA-1.0 CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.5 CC-BY-NC-SA-3.0 CC-BY-NC-SA-4.0
        CC-BY-ND-1.0 CC-BY-ND-2.0 CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-4.0
        CC-BY-SA-1.0 CC-BY-SA-2.0 CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-4.0
        CC0-1.0 CDDL-1.0 CDDL-1.1 CECILL-2.1
        CPL-1.0 CUA-OPL-1.0
        ECL-1.0 ECL-2.0 EFL-1.0 EFL-2.0 Entessa EPL-1.0 EPL-2.0 EUDatagrid EUPL-1.1 EUPL-1.2
        FSFAP FTPL
        GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later
        ICU ISC
        JSON
        LAL-1.2 LAL-1.3 Latex2e LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later
        LiLiQ-P-1.1 LiLiQ-R-1.1 LiLiQ-Rplus-1.1 LPL-1.0 LPL-1.02 LPPL-1.0 LPPL-1.1 LPPL-1.2 LPPL-1.3a LPPL-1.3c
        MIT MIT-0 MPL-1.0 MPL-1.1 MPL-2.0 MPL-2.0-no-copyleft-exception MS-PL MS-RL MulanPSL-2.0
        NCSA Nokia NOASSERTION NONE NPOSL-3.0 NTP
        OGTSL OLDAP-2.8 OFL-1.0 OFL-1.1 OFL-1.1-RFN OSET-PL-2.1 OSL-1.0 OSL-2.0 OSL-2.1 OSL-3.0
        PHP-3.0 PHP-3.01 PostgreSQL PSF-2.0 Python-2.0
        QPL-1.0
        RPL-1.1 RPL-1.5 RPSL-1.0 RSCPL Ruby
        SimPL-2.0 SISSL SleepyCat SPL-1.0
        UCL-1.0 Unicode-DFS-2016 Unlicense UPL-1.0
        Vim VSL-1.0
        W3C Watcom-1.0 WTFPL
        Xnet
        Zlib ZPL-2.0 ZPL-2.1
      ].to_set.freeze

      DEPRECATED_LICENSE_MAP = {
        "AGPL-3.0" => "AGPL-3.0-only",
        "GPL-2.0" => "GPL-2.0-only",
        "GPL-3.0" => "GPL-3.0-only",
        "LGPL-2.1" => "LGPL-2.1-only",
        "LGPL-3.0" => "LGPL-3.0-only",
      }.freeze

      private

      def self.normalize_license_id(license_id)
        return license_id if KNOWN_SPDX_IDS.include?(license_id)

        if mapped = DEPRECATED_LICENSE_MAP[license_id]
          return mapped
        end

        if license_id.start_with?("LicenseRef-")
          license_id
        else
          "LicenseRef-#{license_id}"
        end
      end
      private_class_method :normalize_license_id

      public

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
