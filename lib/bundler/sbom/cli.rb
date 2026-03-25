require "json"
require "bundler/sbom/generator"
require "bundler/sbom/reporter"

module Bundler
  module Sbom
    class CLI < Thor
      desc "dump", "Generate SBOM and save to file"
      method_option :format, type: :string, default: "json", desc: "Output format: json or xml", aliases: "-f"
      method_option :sbom, type: :string, default: "spdx", desc: "SBOM format: spdx or cyclonedx", aliases: "-s"
      method_option :without, type: :string, desc: "Exclude groups (comma or colon separated, e.g., 'development:test' or 'development,test')"
      def dump
        format = options[:format].downcase
        sbom_format = options[:sbom].downcase
        without_groups = parse_without_groups(options[:without])

        unless ["json", "xml"].include?(format)
          raise Thor::Error, "Error: Unsupported output format '#{format}'. Supported formats: json, xml"
        end

        unless ["spdx", "cyclonedx"].include?(sbom_format)
          raise Thor::Error, "Error: Unsupported SBOM format '#{sbom_format}'. Supported formats: spdx, cyclonedx"
        end

        generator = Bundler::Sbom::Generator.new(format: sbom_format, without_groups: without_groups)
        sbom = generator.generate

        ext = (format == "json") ? "json" : "xml"
        prefix = (sbom_format == "spdx") ? "bom" : "bom-cyclonedx"
        output_file = "#{prefix}.#{ext}"

        if format == "json"
          File.write(output_file, JSON.pretty_generate(sbom.to_hash))
        else
          File.write(output_file, sbom.to_xml)
        end

        Bundler.ui.info("Generated #{sbom_format.upcase} SBOM at #{output_file}")
      end

      desc "license", "Display license report from SBOM file"
      method_option :file, type: :string, desc: "Input SBOM file path", aliases: "-f"
      method_option :format, type: :string, desc: "Input format: json or xml", aliases: "-F"
      def license
        format = options[:format]&.downcase
        input_file = options[:file]

        if format && !["json", "xml"].include?(format)
          raise Thor::Error, "Error: Unsupported format '#{format}'. Supported formats: json, xml"
        end

        if input_file.nil?
          input_file = if format == "xml" || (format.nil? && File.exist?("bom.xml"))
            "bom.xml"
          elsif File.exist?("bom-cyclonedx.json")
            "bom-cyclonedx.json"
          elsif File.exist?("bom-cyclonedx.xml")
            "bom-cyclonedx.xml"
          else
            "bom.json"
          end
        end

        unless File.exist?(input_file)
          file_type = (File.extname(input_file) == ".xml") ? "xml" : "json"
          sbom_type = input_file.include?("cyclonedx") ? "cyclonedx" : "spdx"
          raise Thor::Error, "Error: #{input_file} not found. Run 'bundle sbom dump --format=#{file_type} --sbom=#{sbom_type}' first."
        end

        content = File.read(input_file)

        sbom = if format == "xml" || (!format && File.extname(input_file) == ".xml")
          Bundler::Sbom::Generator.parse_xml(content)
        else
          Bundler::Sbom::Generator.from_hash(JSON.parse(content))
        end

        Bundler::Sbom::Reporter.new(sbom).display_license_report
      rescue JSON::ParserError
        raise Thor::Error, "Error: #{input_file} is not a valid JSON file"
      rescue Thor::Error
        raise
      rescue => e
        raise Thor::Error, "Error processing #{input_file}: #{e.message}"
      end

      def self.exit_on_failure?
        true
      end

      private

      def parse_without_groups(without_option)
        return [] unless without_option

        groups = without_option.split(%r{[:,]}).map(&:strip).reject(&:empty?)
        groups.map(&:to_sym)
      end
    end
  end
end
