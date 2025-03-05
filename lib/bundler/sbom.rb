require "bundler"
require "json"
require "securerandom"
require "rubygems"

module Bundler
  module Sbom
    class Generator
      def self.generate_sbom
        lockfile_path = Bundler.default_lockfile
        unless lockfile_path.exist?
          abort "No Gemfile.lock found. Run `bundle install` first."
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)
        spdx_id = SecureRandom.uuid

        sbom = {
          "SPDXID" => "SPDXRef-DOCUMENT",
          "spdxVersion" => "SPDX-2.2",
          "creationInfo" => {
            "created" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators" => ["Tool: bundle-sbom"],
            "licenseListVersion" => "3.17"
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

        sbom
      end

      def self.analyze_licenses(sbom)
        license_count = Hash.new(0)

        sbom["packages"].each do |package|
          license = package["licenseDeclared"]

          if license.include?(",")
            licenses = license.split(",").map(&:strip)
            licenses.each do |lic|
              license_count[lic] += 1
            end
          else
            license_count[license] += 1
          end
        end

        license_count
      end

      def self.display_license_report(sbom)
        license_count = analyze_licenses(sbom)
        sorted_licenses = license_count.sort_by { |_, count| -count }

        puts "=== License Usage in SBOM ==="
        puts "Total packages: #{sbom["packages"].size}"
        puts

        sorted_licenses.each do |license, count|
          puts "#{license}: #{count} package(s)"
        end

        puts "\n=== Packages by License ==="
        sorted_licenses.each do |license, _|
          packages = sbom["packages"].select do |package|
            if package["licenseDeclared"].include?(",")
              package["licenseDeclared"].split(",").map(&:strip).include?(license)
            else
              package["licenseDeclared"] == license
            end
          end

          puts "\n#{license} (#{packages.size} package(s)):"
          packages.each do |package|
            puts "  - #{package["name"]} (#{package["versionInfo"]})"
          end
        end
      end
    end
  end
end