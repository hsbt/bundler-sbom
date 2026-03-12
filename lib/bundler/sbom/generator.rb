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
      def initialize(format: "spdx", without_groups: [])
        @format = format.to_s.downcase
        @without_groups = without_groups
      end

      def generate
        lockfile_path = Bundler.default_lockfile
        if !lockfile_path || !lockfile_path.exist?
          Bundler.ui.error "No Gemfile.lock found. Run `bundle install` first."
          raise GemfileLockNotFoundError, "No Gemfile.lock found"
        end

        lockfile = Bundler::LockfileParser.new(lockfile_path.read)
        document_name = File.basename(Dir.pwd)

        gems = get_gems_for_groups(lockfile)
        gem_data = resolve_gem_data(gems)

        case @format
        when "cyclonedx"
          CycloneDX.generate(gem_data, document_name)
        else
          SPDX.generate(gem_data, document_name)
        end
      end

      def self.parse_xml(xml_content)
        doc = REXML::Document.new(xml_content)
        root = doc.root

        if root.name == "bom" && root.namespace.include?("cyclonedx.org")
          CycloneDX.parse_xml(doc)
        else
          SPDX.parse_xml(doc)
        end
      end

      def self.from_hash(hash)
        if hash["bomFormat"] == "CycloneDX"
          CycloneDX.new(hash)
        else
          SPDX.new(hash)
        end
      end

      private

      def get_gems_for_groups(lockfile)
        if @without_groups.empty?
          return lockfile.specs
        end

        if defined?(Bundler::Definition) && Bundler.respond_to?(:definition)
          begin
            definition = Bundler.definition
            all_groups = definition.groups
            include_groups = all_groups - @without_groups

            if definition.respond_to?(:specs_for)
              definition.specs_for(include_groups)
            else
              included_gems = Set.new
              include_groups.each do |group|
                definition.dependencies_for(group).each do |dep|
                  included_gems.add(dep.name)
                end
              end
              lockfile.specs.select { |spec| included_gems.include?(spec.name) }
            end
          rescue => e
            Bundler.ui.warn("Warning: Could not determine group information: #{e.message}")
            lockfile.specs
          end
        else
          lockfile.specs
        end
      end

      def resolve_gem_data(gems)
        seen = Set.new
        gems.filter_map do |spec|
          gem_key = "#{spec.name}:#{spec.version}"
          next if seen.include?(gem_key)
          seen.add(gem_key)
          {name: spec.name, version: spec.version.to_s, licenses: SpecLicenseFinder.find_licenses(spec)}
        end
      end
    end
  end
end
