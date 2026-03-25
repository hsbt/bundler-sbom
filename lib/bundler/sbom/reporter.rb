module Bundler
  module Sbom
    class Reporter
      def initialize(sbom)
        @sbom = sbom
      end

      def display_license_report
        report = @sbom.to_report_format
        display_report(report)
      end

      private

      def display_report(report)
        license_count = analyze_licenses(report)
        sorted_licenses = license_count.sort_by { |_, count| -count }

        Bundler.ui.info "=== License Usage in SBOM ==="
        Bundler.ui.info "Total packages: #{report["packages"].size}"
        Bundler.ui.info ""

        sorted_licenses.each do |license, count|
          Bundler.ui.info "#{license}: #{count} package(s)"
        end

        Bundler.ui.info "\n=== Packages by License ==="
        sorted_licenses.each do |license, _|
          packages = report["packages"].select do |package|
            split_licenses(package["licenseDeclared"]).include?(license)
          end

          Bundler.ui.info "\n#{license} (#{packages.size} package(s)):"
          packages.each do |package|
            Bundler.ui.info "  - #{package["name"]} (#{package["versionInfo"]})"
          end
        end
      end

      def analyze_licenses(report)
        license_count = Hash.new(0)
        report["packages"].each do |package|
          split_licenses(package["licenseDeclared"]).each do |license|
            license_count[license] += 1
          end
        end
        license_count
      end

      def split_licenses(license_declared)
        license_declared.split(/ AND |, /).map(&:strip)
      end
    end
  end
end
