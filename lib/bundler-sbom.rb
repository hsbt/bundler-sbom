require "bundler/cli/sbom"

Bundler::Plugin.add_command("sbom", Bundler::CLI::Sbom)