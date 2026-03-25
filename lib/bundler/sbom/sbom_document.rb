require "rexml/document"

module Bundler
  module Sbom
    module SbomDocument
      def self.included(base)
        base.attr_reader :data
        base.extend(ClassMethods)
      end

      def initialize(data)
        @data = data
      end

      def to_hash
        @data
      end

      module ClassMethods
        private

        def get_element_text(element, xpath)
          result = REXML::XPath.first(element, xpath)
          result ? result.text : nil
        end
      end

      private

      def add_element(parent, name, value)
        element = REXML::Element.new(name)
        element.text = value
        parent.add_element(element)
      end

      def format_xml(doc)
        formatter = REXML::Formatters::Pretty.new(2)
        formatter.compact = true
        output = ""
        formatter.write(doc, output)
        output.sub(%r{<\?xml version='1\.0' encoding='UTF-8'\?>}, '<?xml version="1.0" encoding="UTF-8"?>')
      end
    end
  end
end
