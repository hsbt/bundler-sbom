require "bundler/cli"
require "bundler/sbom"

module Bundler
  class CLI::Sbom
    def initialize(options = {})
      @options = options
    end

    def dump
      sbom = Bundler::Sbom::Generator.generate_sbom
      File.write("bom.json", JSON.pretty_generate(sbom))
      Bundler.ui.info "Generated SBOM at bom.json"
    end

    def license
      begin
        sbom = JSON.parse(File.read("bom.json"))
        Bundler::Sbom::Generator.display_license_report(sbom)
      rescue Errno::ENOENT
        Bundler.ui.error "Error: bom.json not found. Run 'bundle sbom dump' first."
        exit 1
      rescue JSON::ParserError
        Bundler.ui.error "Error: bom.json is not a valid JSON file"
        exit 1
      end
    end
  end
end