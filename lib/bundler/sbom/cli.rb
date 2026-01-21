require "json"
require "bundler/sbom/generator"
require "bundler/sbom/reporter"

module Bundler
  module Sbom
    class CLI < Thor
      desc "dump", "Generate SBOM and save to file"
      method_option :format, type: :string, default: "json", desc: "Output format: json or xml", aliases: "-f"
      method_option :sbom, type: :string, default: "spdx", desc: "SBOM format: spdx or cyclonedx", aliases: "-s"
      def dump
        format = options[:format].downcase
        sbom_format = options[:sbom].downcase

        # Validate output format
        unless ["json", "xml"].include?(format)
          Bundler.ui.error("Error: Unsupported output format '#{format}'. Supported formats: json, xml")
          exit 1
        end

        # Validate SBOM format
        unless ["spdx", "cyclonedx"].include?(sbom_format)
          Bundler.ui.error("Error: Unsupported SBOM format '#{sbom_format}'. Supported formats: spdx, cyclonedx")
          exit 1
        end

        # Generate SBOM based on specified format
        sbom = Bundler::Sbom::Generator.generate_sbom(sbom_format)

        # Determine file extension based on output format
        ext = (format == "json") ? "json" : "xml"

        # Determine filename prefix based on SBOM format
        prefix = (sbom_format == "spdx") ? "bom" : "bom-cyclonedx"
        output_file = "#{prefix}.#{ext}"

        if format == "json"
          File.write(output_file, JSON.pretty_generate(sbom))
        else # xml
          xml_content = Bundler::Sbom::Generator.convert_to_xml(sbom)
          File.write(output_file, xml_content)
        end

        Bundler.ui.info("Generated #{sbom_format.upcase} SBOM at #{output_file}")
      end

      desc "license", "Display license report from SBOM file"
      method_option :file, type: :string, desc: "Input SBOM file path", aliases: "-f"
      method_option :format, type: :string, desc: "Input format: json or xml", aliases: "-F"
      def license
        format = options[:format]&.downcase
        input_file = options[:file]

        # Validate format if provided
        if format && !["json", "xml"].include?(format)
          Bundler.ui.error("Error: Unsupported format '#{format}'. Supported formats: json, xml")
          exit 1
        end

        # Determine input file based on format or find default files
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
          Bundler.ui.error("Error: #{input_file} not found. Run 'bundle sbom dump --format=#{file_type} --sbom=#{sbom_type}' first.")
          exit 1
        end

        begin
          content = File.read(input_file)

          sbom = if format == "xml" || (!format && File.extname(input_file) == ".xml")
            Bundler::Sbom::Generator.parse_xml(content)
          else
            JSON.parse(content)
          end

          Bundler::Sbom::Reporter.display_license_report(sbom)
        rescue JSON::ParserError
          Bundler.ui.error("Error: #{input_file} is not a valid JSON file")
          exit 1
        rescue => e
          Bundler.ui.error("Error processing #{input_file}: #{e.message}")
          exit 1
        end
      end

      # 適切にエラーで終了することを保証するためのメソッド
      def self.exit_on_failure?
        true
      end
    end
  end
end
