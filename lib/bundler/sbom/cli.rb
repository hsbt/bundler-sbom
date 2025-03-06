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
      
      desc "license", "Display license report from existing SBOM file"
      method_option :format, type: :string, default: "json", desc: "Input format: json or xml", aliases: "-f"
      def license
        format = options[:format].downcase
        unless ["json", "xml"].include?(format)
          Bundler.ui.error("Error: Unsupported format '#{format}'. Supported formats: json, xml")
          exit 1
        end
        
        input_file = format == "json" ? "bom.json" : "bom.xml"
        
        unless File.exist?(input_file)
          Bundler.ui.error("Error: #{input_file} not found. Run 'bundle sbom dump --format=#{format}' first.")
          exit 1
        end
        
        begin
          sbom = if format == "json"
            JSON.parse(File.read(input_file))
          else
            Bundler::Sbom::Generator.parse_xml(File.read(input_file))
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
    end
  end
end