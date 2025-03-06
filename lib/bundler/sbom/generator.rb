require "bundler"
require "securerandom"
require "json"
require "rexml/document"
require "bundler/sbom/spdx"
require "bundler/sbom/cyclonedx"

module Bundler
  module Sbom
    class GemfileLockNotFoundError < StandardError; end

    class Generator
      def self.generate_sbom(format = "spdx")
        lockfile_path = Bundler.default_lockfile
        if !lockfile_path || !lockfile_path.exist?
          Bundler.ui.error "No Gemfile.lock found. Run `bundle install` first."
          raise GemfileLockNotFoundError, "No Gemfile.lock found"
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)

        case format.to_s.downcase
        when "cyclonedx"
          CycloneDX.generate(lockfile, document_name)
        else # default to spdx
          SPDX.generate(lockfile, document_name)
        end
      end

      def self.convert_to_xml(sbom)
        if sbom["bomFormat"] == "CycloneDX"
          CycloneDX.to_xml(sbom)
        else
          SPDX.to_xml(sbom)
        end
      end

      def self.parse_xml(xml_content)
        doc = REXML::Document.new(xml_content)
        root = doc.root
        
        # Determine if it's CycloneDX or SPDX
        if root.name == "bom" && root.namespace.include?("cyclonedx.org")
          CycloneDX.parse_xml(doc)
        else
          SPDX.parse_xml(doc)
        end
      end
    end
  end
end