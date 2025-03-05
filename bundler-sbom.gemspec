require_relative "lib/bundler/sbom/version"

Gem::Specification.new do |spec|
  spec.name          = "bundler-sbom"
  spec.version       = Bundler::Sbom::VERSION
  spec.authors       = ["SHIBATA Hiroshi"]
  spec.email         = ["hsbt@ruby-lang.org"]

  spec.summary       = "Generate CycloneDX SBOM(Software Bill of Materials) files with Bundler"
  spec.description   = spec.summary
  spec.homepage      = "https://github.com/hsbt/bundler-sbom"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.files         = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) || f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor])
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "bundler", ">= 2.0"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues"
  }
end