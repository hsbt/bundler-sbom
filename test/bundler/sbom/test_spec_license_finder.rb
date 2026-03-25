require "test_helper"

class Bundler::Sbom::SpecLicenseFinderTest < Minitest::Test
  include TestHelper

  def make_double(methods)
    obj = Object.new
    methods.each do |name, value|
      if value.is_a?(Proc)
        obj.define_singleton_method(name, &value)
      else
        obj.define_singleton_method(name) { value }
      end
    end
    obj
  end

  # -- when spec supports __materialize__ --

  def test_uses_materialized_gemspec_for_license_lookup
    materialized_gemspec = make_double(
      license: "BSD-2-Clause",
      licenses: ["BSD-2-Clause"]
    )
    spec = make_double(
      name: "colorize",
      version: Gem::Version.new("1.0.0"),
      __materialize__: materialized_gemspec
    )

    Gem::Specification.stub(:find_by_name, nil) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["BSD-2-Clause"], licenses
    end
  end

  def test_prefers_materialized_gemspec_over_global
    materialized_gemspec = make_double(
      license: "BSD-2-Clause",
      licenses: ["BSD-2-Clause"]
    )
    spec = make_double(
      name: "colorize",
      version: Gem::Version.new("1.0.0"),
      __materialize__: materialized_gemspec
    )

    globally_installed = make_double(
      license: "MIT",
      licenses: ["MIT"]
    )

    Gem::Specification.stub(:find_by_name, globally_installed) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["BSD-2-Clause"], licenses
    end
  end

  def test_falls_back_to_find_by_name_when_materialize_returns_nil
    spec = make_double(
      name: "rake",
      version: Gem::Version.new("13.0.6"),
      __materialize__: nil
    )

    globally_installed = make_double(
      license: "MIT",
      licenses: ["MIT"]
    )

    Gem::Specification.stub(:find_by_name, globally_installed) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["MIT"], licenses
    end
  end

  def test_returns_empty_array_when_materialize_nil_and_find_by_name_raises
    spec = make_double(
      name: "colorize",
      version: Gem::Version.new("1.0.0"),
      __materialize__: nil
    )

    Gem::Specification.stub(:find_by_name, proc { raise Gem::LoadError }) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal [], licenses
    end
  end

  # -- when spec does not support __materialize__ --

  def test_falls_back_to_find_by_name
    spec = make_double(
      name: "rake",
      version: Gem::Version.new("13.0.6")
    )

    gemspec = make_double(
      license: "MIT",
      licenses: ["MIT"]
    )

    Gem::Specification.stub(:find_by_name, gemspec) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["MIT"], licenses
    end
  end

  # -- when spec supports materialize_for_installation (Bundler >= 2.7) --

  def test_uses_materialize_for_installation
    materialized_gemspec = make_double(
      license: "GPL-2.0-only",
      licenses: ["GPL-2.0-only", "GPL-3.0-only"]
    )
    spec = make_double(
      name: "ttfunk",
      version: Gem::Version.new("1.8.0"),
      materialize_for_installation: materialized_gemspec
    )

    Gem::Specification.stub(:find_by_name, nil) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["GPL-2.0-only", "GPL-3.0-only"], licenses
    end
  end

  def test_falls_back_when_materialize_for_installation_raises_gemspec_error
    spec = Object.new
    spec.define_singleton_method(:name) { "my-gem" }
    spec.define_singleton_method(:version) { Gem::Version.new("1.0.0") }
    spec.define_singleton_method(:materialize_for_installation) { raise Bundler::GemspecError, "custom DSL method not available" }

    gemspec = make_double(
      license: "MIT",
      licenses: ["MIT"]
    )

    Gem::Specification.stub(:find_by_name, gemspec) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["MIT"], licenses
    end
  end

  def test_falls_back_when_materialize_for_installation_returns_self_without_licenses
    spec = Object.new
    spec.define_singleton_method(:name) { "overmind" }
    spec.define_singleton_method(:version) { Gem::Version.new("2.0.0") }
    spec.define_singleton_method(:materialize_for_installation) { self }

    gemspec = make_double(
      license: "MIT",
      licenses: ["MIT"]
    )

    Gem::Specification.stub(:find_by_name, gemspec) do
      licenses = Bundler::Sbom::SpecLicenseFinder.find_licenses(spec)
      assert_equal ["MIT"], licenses
    end
  end
end
