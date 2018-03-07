#!/usr/local/bin/ruby
# encoding: utf-8
# author: Matthew Dromazos

require 'nokogiri'
require 'json'
require_relative 'StigAttributes'
require_relative 'CCIAttributes'

class Xccdf2Inspec
  def initialize(xccdf_path, cci_path)
    @cci_xml = File.read(cci_path)
    @xccdf_xml = File.read(xccdf_path)
    create_controls
  end
  
  def create_controls
    @cci_items = CCI_List.parse(@cci_xml)
    @xccdf_controls = Benchmark.parse(@xccdf_xml)
    require 'pry'
    binding.pry
  end
end