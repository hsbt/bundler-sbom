module Bundler
  module Sbom
    module SpecLicenseFinder
      def self.find_licenses(spec)
        gemspec = spec.__materialize__ if spec.respond_to?(:__materialize__)
        begin
          gemspec ||= Gem::Specification.find_by_name(spec.name, spec.version)
        rescue Gem::LoadError
          # ignore
        end

        licenses = []
        if gemspec
          if gemspec.respond_to?(:license) && gemspec.license && !gemspec.license.empty?
            licenses << gemspec.license
          end
          if gemspec.respond_to?(:licenses) && gemspec.licenses && !gemspec.licenses.empty?
            licenses.concat(gemspec.licenses)
          end
          licenses.uniq!
        end
        licenses
      end
    end
  end
end
