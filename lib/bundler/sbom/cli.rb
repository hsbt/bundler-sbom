require "json"
require "bundler/sbom/generator"
require "bundler/sbom/reporter"

module Bundler
  module Sbom
    class CLI < Thor
      desc "dump", "Generate SBOM and save to file"
      method_option :format, type: :string, default: "json", desc: "Output format: json or xml", aliases: "-f"
      def dump
        format = options[:format].downcase
        unless ["json", "xml"].include?(format)
          Bundler.ui.error("Error: Unsupported format '#{format}'. Supported formats: json, xml")
          exit 1
        end

        sbom = Bundler::Sbom::Generator.generate_sbom
        
        if format == "json"
          output_file = "bom.json"
          File.write(output_file, JSON.pretty_generate(sbom))
        else # xml
          output_file = "bom.xml"
          xml_content = Bundler::Sbom::Generator.convert_to_xml(sbom)
          File.write(output_file, xml_content)
        end
        
        Bundler.ui.info("Generated SBOM at #{output_file}")
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
          if format == "xml" || (format.nil? && File.exist?("bom.xml"))
            input_file = "bom.xml"
          else
            input_file = "bom.json"
          end
        end

        unless File.exist?(input_file)
          file_type = File.extname(input_file) == ".xml" ? "xml" : "json"
          Bundler.ui.error("Error: #{input_file} not found. Run 'bundle sbom dump --format=#{file_type}' first.")
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
        rescue StandardError => e
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