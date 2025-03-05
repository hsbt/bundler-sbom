lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "bundler-sbom"
  spec.version       = "0.1.2"
  spec.authors       = ["SHIBATA Hiroshi"]
  spec.email         = ["hsbt@ruby-lang.org"]

  spec.summary       = %q{Bundler plugin to generate and analyze SBOM}
  spec.description   = %q{Generate SPDX format SBOM from Gemfile.lock and analyze license information}
  spec.homepage      = "https://github.com/hsbt/bundler-sbom"
  spec.license       = "MIT"

  spec.files         = Dir.glob("{exe,lib}/**/*") + %w(README.md plugins.rb)
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues"
  }
end