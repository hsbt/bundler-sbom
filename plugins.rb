require "bundler/cli/sbom"

Bundler::Plugin::API.command "sbom" do |command|
  command.command "dump" do
    Bundler::CLI::Sbom.new.dump
  end

  command.command "license" do
    Bundler::CLI::Sbom.new.license
  end
end