require "bundler/cli/sbom"

Bundler::Plugin::API.command("sbom", Bundler::CLI::Sbom)