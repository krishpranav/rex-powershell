require 'spec_helper'

def decompress(code)
    Rex::Powershell::Script.new(code).decompress_code
end

RSpec.describe Rex::Powershell::Command do
    let(:example_script) do
        File.join('spec', 'file_fixtures', 'powerdump.ps1')
    end

    let(:payload) do
        Rex::Text.rand_text_alpha(120)
    end

    let(:arch) do
        'x86'
    end
    