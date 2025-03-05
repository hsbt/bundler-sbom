require "bundler"
require "bundler/sbom"

module Bundler
  module Sbom
    class Plugin < ::Bundler::Plugin::API
      command "sbom"

      def exec(command_name, args)
        ::Bundler::Sbom::CLI.start(args)
      end
    end
  end
end
