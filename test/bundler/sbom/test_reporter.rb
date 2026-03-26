require "test_helper"

class Bundler::Sbom::ReporterTest < Minitest::Test
  include TestHelper

  def simple_sbom
    Bundler::Sbom::SPDX.new({
      "packages" => [
        {
          "name" => "rake",
          "versionInfo" => "13.0.6",
          "licenseDeclared" => "MIT"
        },
        {
          "name" => "bundler",
          "versionInfo" => "2.4.0",
          "licenseDeclared" => "MIT, Apache-2.0"
        }
      ]
    })
  end

  def empty_sbom
    Bundler::Sbom::SPDX.new({
      "packages" => []
    })
  end

  def test_display_license_report_outputs_formatted_report
    out, = capture_io { Bundler::Sbom::Reporter.new(simple_sbom).display_license_report }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_display_license_report_handles_no_license
    sbom_with_no_license = Bundler::Sbom::SPDX.new({
      "packages" => [
        {
          "name" => "unlicensed-gem",
          "versionInfo" => "1.0.0",
          "licenseDeclared" => "NOASSERTION"
        }
      ]
    })
    out, = capture_io { Bundler::Sbom::Reporter.new(sbom_with_no_license).display_license_report }
    assert_match(/NOASSERTION: 1 package\(s\)/, out)
  end

  def test_display_license_report_empty_packages
    out, = capture_io { Bundler::Sbom::Reporter.new(empty_sbom).display_license_report }
    assert_match(/Total packages: 0/, out)
  end

  # CycloneDX format tests

  def test_display_license_report_cyclonedx
    cyclonedx_sbom = Bundler::Sbom::CycloneDX.new({
      "bomFormat" => "CycloneDX",
      "components" => [
        {
          "name" => "rake",
          "version" => "13.0.6",
          "licenses" => [{"license" => {"id" => "MIT"}}]
        }
      ]
    })
    out, = capture_io { Bundler::Sbom::Reporter.new(cyclonedx_sbom).display_license_report }
    assert_match(/License Usage in SBOM/, out)
  end

  def test_display_license_report_cyclonedx_no_license
    no_license_sbom = Bundler::Sbom::CycloneDX.new({
      "bomFormat" => "CycloneDX",
      "components" => [
        {
          "name" => "unlicensed-gem",
          "version" => "1.0.0"
        }
      ]
    })
    out, = capture_io { Bundler::Sbom::Reporter.new(no_license_sbom).display_license_report }
    assert_match(/NOASSERTION: 1 package\(s\)/, out)
  end

  def test_display_license_report_cyclonedx_empty_components
    empty_cyclonedx_sbom = Bundler::Sbom::CycloneDX.new({
      "bomFormat" => "CycloneDX",
      "components" => []
    })
    out, = capture_io { Bundler::Sbom::Reporter.new(empty_cyclonedx_sbom).display_license_report }
    assert_match(/Total packages: 0/, out)
  end
end
