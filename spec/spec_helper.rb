require "simplecov"
SimpleCov.start do
  add_filter "/spec/"
  minimum_coverage 98
end

require "bundler"
require "bundler/sbom"
require "rspec/its"
require "tmpdir"
require "fileutils"

module SpecHelper
  def self.root
    @root ||= Pathname.new(File.expand_path("../..", __FILE__))
  end

  def self.reset_env!
    ENV.delete_if { |k,_| k.start_with?("BUNDLER_") }
    ENV["BUNDLE_DISABLE_POSTIT"] = "1"
    ENV["BUNDLE_USER_CONFIG"] = "/dev/null"
    ENV["BUNDLE_USER_CACHE"] = "/dev/null"
    ENV["BUNDLE_USER_PATH"] = "/dev/null"
    ENV["BUNDLE_GEMFILE"] = "#{root}/Gemfile"
  end

  def self.with_temp_dir
    dir = Dir.mktmpdir
    begin
      yield Pathname.new(dir)
    ensure
      FileUtils.remove_entry(dir) if Dir.exist?(dir)
    end
  end
end

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.filter_run_when_matching :focus
  config.example_status_persistence_file_path = "spec/examples.txt"
  config.disable_monkey_patching!
  config.warnings = true

  config.default_formatter = "doc" if config.files_to_run.one?

  config.order = :random
  Kernel.srand config.seed

  config.before(:each) do
    SpecHelper.reset_env!
  end
end
