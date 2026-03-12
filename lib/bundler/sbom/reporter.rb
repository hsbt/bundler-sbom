module Bundler
  module Sbom
    class Reporter
      def self.display_license_report(sbom)
        # フォーマットに応じて適切な形式に変換
        sbom = if sbom_format(sbom) == :cyclonedx
          CycloneDX.to_report_format(sbom)
        else
          SPDX.to_report_format(sbom)
        end

        display_report(sbom)
      end

      private

      def self.sbom_format(sbom)
        return :cyclonedx if sbom["bomFormat"] == "CycloneDX"
        :spdx
      end

      def self.display_report(sbom)
        license_count = analyze_licenses(sbom)
        sorted_licenses = license_count.sort_by { |_, count| -count }

        Bundler.ui.info "=== License Usage in SBOM ==="
        Bundler.ui.info "Total packages: #{sbom["packages"].size}"
        Bundler.ui.info ""

        sorted_licenses.each do |license, count|
          Bundler.ui.info "#{license}: #{count} package(s)"
        end

        Bundler.ui.info "\n=== Packages by License ==="
        sorted_licenses.each do |license, _|
          packages = sbom["packages"].select do |package|
            if package["licenseDeclared"].include?(",")
              package["licenseDeclared"].split(",").map(&:strip).include?(license)
            else
              package["licenseDeclared"] == license
            end
          end

          Bundler.ui.info "\n#{license} (#{packages.size} package(s)):"
          packages.each do |package|
            Bundler.ui.info "  - #{package["name"]} (#{package["versionInfo"]})"
          end
        end
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
