module Bundler
  module Sbom
    module SpecLicenseFinder
      def self.find_licenses(spec)
        gemspec = begin
          mat = spec.materialize_for_installation if spec.respond_to?(:materialize_for_installation)
          mat if mat.respond_to?(:licenses)
        rescue Bundler::GemspecError
          nil
        end

        begin
          gemspec ||= spec.__materialize__ if spec.respond_to?(:__materialize__)
        rescue Bundler::GemspecError
          # ignore
        end

        begin
          gemspec ||= Gem::Specification.find_by_name(spec.name, spec.version)
        rescue Gem::LoadError
          Bundler.ui.warn("Warning: Could not find license information for #{spec.name} (#{spec.version})")
        end

        if gemspec && gemspec.respond_to?(:licenses) && gemspec.licenses && !gemspec.licenses.empty?
          gemspec.licenses
        else
          []
        end
      end
    end
  end
end
