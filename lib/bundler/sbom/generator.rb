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
      def self.generate_sbom(format = "spdx", without_groups: [])
        lockfile_path = Bundler.default_lockfile
        if !lockfile_path || !lockfile_path.exist?
          Bundler.ui.error "No Gemfile.lock found. Run `bundle install` first."
          raise GemfileLockNotFoundError, "No Gemfile.lock found"
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)

        # Get gems to include based on groups
        gems = get_gems_for_groups(lockfile, without_groups)

        case format.to_s.downcase
        when "cyclonedx"
          CycloneDX.generate(gems, document_name)
        else # default to spdx
          SPDX.generate(gems, document_name)
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

      private

      def self.get_gems_for_groups(lockfile, without_groups)
        # If no groups specified, use all specs
        if without_groups.empty?
          return lockfile.specs
        end

        # Try to get group information from Bundler.definition if available
        if defined?(Bundler::Definition) && Bundler.respond_to?(:definition)
          begin
            definition = Bundler.definition
            all_groups = definition.groups
            include_groups = all_groups - without_groups

            # Get dependencies for included groups
            included_gems = Set.new
            include_groups.each do |group|
              definition.dependencies_for(group).each do |dep|
                included_gems.add(dep.name)
              end
            end

            # Filter specs based on included gems
            lockfile.specs.select { |spec| included_gems.include?(spec.name) }
          rescue => e
            # Fallback to all specs if there's any issue with Bundler.definition
            Bundler.ui.warn("Warning: Could not determine group information: #{e.message}")
            lockfile.specs
          end
        else
          lockfile.specs
        end
      end
    end
  end
end
