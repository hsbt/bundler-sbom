require "simplecov"
SimpleCov.start do
  add_filter "/test/"
  minimum_coverage 98
end

require "minitest/autorun"
require "minitest/mock"
require "bundler"
require "bundler/sbom"
require "tmpdir"
require "fileutils"

module TestHelper
  def self.root
    @root ||= Pathname.new(File.expand_path("../..", __FILE__))
  end

  def self.reset_env!
    ENV.delete_if { |k, _| k.start_with?("BUNDLER_") }
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

  def with_temp_dir(&block)
    TestHelper.with_temp_dir(&block)
  end

  def setup
    TestHelper.reset_env!
  end
end
