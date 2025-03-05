require "bundler"

module Bundler
  module Sbom
    VERSION = "0.1.1"
  end
end

require "bundler/sbom/generator"
require "bundler/sbom/cli"