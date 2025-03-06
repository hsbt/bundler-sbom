module Bundler
  module Sbom
    class Reporter
      def self.display_license_report(sbom)
        # Detect SBOM format
        if sbom_format(sbom) == :cyclonedx
          # Convert CycloneDX to a format compatible with our reporter
          sbom = convert_cyclonedx_to_report_format(sbom)
        end
        
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

      private

      # Detect if SBOM is in CycloneDX format
      def self.sbom_format(sbom)
        return :cyclonedx if sbom["bomFormat"] == "CycloneDX"
        return :spdx # default format
      end

      # Convert CycloneDX format to a structure compatible with our reporter
      def self.convert_cyclonedx_to_report_format(sbom)
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

      def self.analyze_licenses(sbom)
        license_count = Hash.new(0)
        sbom["packages"].each do |package|
          licenses = package["licenseDeclared"].split(",").map(&:strip)
          licenses.each do |license|
            license_count[license] += 1
          end
        end
        license_count
      end
    end
  end
end