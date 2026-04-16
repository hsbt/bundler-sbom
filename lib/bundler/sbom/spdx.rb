require "bundler"
require "securerandom"
require "spdx-licenses"
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
            "creators" => ["Tool: bundle-sbom"]
          },
          "name" => document_name,
          "dataLicense" => "CC0-1.0",
          "documentNamespace" => "https://spdx.org/spdxdocs/#{document_name}-#{spdx_id}",
          "packages" => []
        }

        if (list_version = license_list_version)
          sbom["creationInfo"]["licenseListVersion"] = list_version
        end

        package_ids = {}
        gem_data.each do |gem|
          package_ids[gem[:name]] = "SPDXRef-Package-#{gem[:name]}"
        end

        gem_data.each do |gem|
          spdx_licenses = gem[:licenses].map { |l| normalize_license_id(l) }
          license_string = spdx_licenses.empty? ? "NOASSERTION" : spdx_licenses.join(" AND ")

          package = {
            "SPDXID" => package_ids[gem[:name]],
            "name" => gem[:name],
            "versionInfo" => gem[:version],
            "downloadLocation" => "https://rubygems.org/gems/#{gem[:name]}/versions/#{gem[:version]}",
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

        sbom["relationships"] = sbom["packages"].map do |p|
          {
            "spdxElementId" => "SPDXRef-DOCUMENT",
            "relatedSpdxElement" => p["SPDXID"],
            "relationshipType" => "DESCRIBES"
          }
        end

        gem_data.each do |gem|
          (gem[:dependencies] || []).each do |dep_name|
            dep_id = package_ids[dep_name]
            next unless dep_id
            sbom["relationships"] << {
              "spdxElementId" => package_ids[gem[:name]],
              "relatedSpdxElement" => dep_id,
              "relationshipType" => "DEPENDS_ON"
            }
          end
        end

        new(sbom)
      end

      DEPRECATED_LICENSE_MAP = {
        "AGPL-3.0" => "AGPL-3.0-only",
        "GPL-2.0" => "GPL-2.0-only",
        "GPL-3.0" => "GPL-3.0-only",
        "LGPL-2.1" => "LGPL-2.1-only",
        "LGPL-3.0" => "LGPL-3.0-only",
      }.freeze

      def self.normalize_license_id(license_id)
        if mapped = DEPRECATED_LICENSE_MAP[license_id]
          return mapped
        end

        return license_id if SpdxLicenses.exist?(license_id)

        if license_id.start_with?("LicenseRef-")
          license_id
        else
          "LicenseRef-#{license_id}"
        end
      end
      private_class_method :normalize_license_id

      def self.license_list_version
        return @license_list_version if defined?(@license_list_version)
        gem_spec = Gem.loaded_specs["spdx-licenses"]
        path = File.join(gem_spec.full_gem_path, "licenses.json")
        @license_list_version = JSON.parse(File.read(path))["licenseListVersion"]
      rescue StandardError
        @license_list_version = nil
      end
      private_class_method :license_list_version

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
