require "json"
require "bundler/sbom/generator"

module Bundler
  module Sbom
    class CLI < Thor
      desc "dump", "Generate SBOM and save to bom.json"
      def dump
        sbom = Bundler::Sbom::Generator.generate_sbom
        File.write("bom.json", JSON.pretty_generate(sbom))
        Bundler.ui.info("Generated SBOM at bom.json")
      end

      desc "license", "Display license report from existing bom.json"
      def license
        unless File.exist?("bom.json")
          Bundler.ui.error("Error: bom.json not found. Run 'bundle sbom dump' first.")
          exit 1
        end

        begin
          sbom = JSON.parse(File.read("bom.json"))
          Bundler::Sbom::Generator.display_license_report(sbom)
        rescue JSON::ParserError
          Bundler.ui.error("Error: bom.json is not a valid JSON file")
          exit 1
        end
      end
    end
  end
end