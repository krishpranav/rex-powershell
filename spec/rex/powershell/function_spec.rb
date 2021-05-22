require 'spec_helper'
require 'rex/powershell'

RSpec.describe Rex::Powershell::Function do

    let(:function_name) do
        Rex::Text.rand_text_alpha(15)
    end
    