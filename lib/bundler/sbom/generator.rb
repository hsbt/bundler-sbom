require "bundler"
require "securerandom"

module Bundler
  module Sbom
    class GemfileLockNotFoundError < StandardError; end

    class Generator
      def self.generate_sbom
        lockfile_path = Bundler.default_lockfile
        if !lockfile_path || !lockfile_path.exist?
          Bundler.ui.error "No Gemfile.lock found. Run `bundle install` first."
          raise GemfileLockNotFoundError, "No Gemfile.lock found"
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)
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
    end
  end
end