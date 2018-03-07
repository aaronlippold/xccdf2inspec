#!/usr/local/bin/ruby
# encoding: utf-8
# author: Matthew Dromazos

require 'nokogiri'
require 'json'
require_relative 'StigAttributes'
require_relative 'CCIAttributes'
require 'inspec/objects'
require 'word_wrap'


class Xccdf2Inspec
  def initialize(xccdf_path, cci_path, output, output_format)
    @cci_xml = File.read(cci_path)
    @xccdf_xml = File.read(xccdf_path)
    @output = 'inspec_profile' if output.nil?
    @output = output unless output.nil?
    @format = 'ruby' if output_format.nil?
    @format = output_format unless output.nil?
    @controls = []
    parse_xmls
    parse_controls
    generate_controls
  end
  
  private
  
  def wrap(s, width = 78)
    s.gsub!(/\\r/, "   \n")
    WordWrap.ww(s.to_s, width)
  end
  
  def parse_xmls
    @cci_items = CCI_List.parse(@cci_xml)
    @xccdf_controls = Benchmark.parse(@xccdf_xml)
  end
  
  def parse_controls
    @xccdf_controls.group.each do |group|
      control = Inspec::Control.new
      control.id     = group.id
      control.title  = group.rule.title
      control.desc   = group.rule.description 
      control.impact = get_impact(group.rule.severity)
      control.add_tag(Inspec::Tag.new('gtitle',   group.title))
      control.add_tag(Inspec::Tag.new('gid',      group.id))
      control.add_tag(Inspec::Tag.new('rid',      group.rule.id))
      control.add_tag(Inspec::Tag.new('stig_id',  group.rule.version))
      control.add_tag(Inspec::Tag.new('cci', group.rule.idents))
      control.add_tag(Inspec::Tag.new('nist', @cci_items.fetch_nists(group.rule.idents)))
      control.add_tag(Inspec::Tag.new('check', group.rule.check.check_content))
      control.add_tag(Inspec::Tag.new('fix', group.rule.fixtext))
      control.add_tag(Inspec::Tag.new('fix_id', group.rule.fix.id))
      
      @controls << control
    end
  end
  
  def generate_controls   
    require 'pry'
    binding.pry 
    Dir.mkdir "#{@output}" unless Dir.exist?("#{@output}")  
    Dir.mkdir "#{@output}/controls" unless Dir.exist?("#{@output}/controls")  
    
    @controls.each do |control|
      if @format == 'ruby'
        file_name = control.id.to_s
        myfile = File.new("#{@output}/controls/#{file_name}.rb", 'w')
        width = 80
        myfile.puts wrap(control.to_ruby)
        myfile.close
      else
        file_name = control.id.to_s
        myfile = File.new("#{@output}/controls/#{file_name}.rb", 'w')
        width = 80
        myfile.puts wrap(control.to_hash)
        myfile.close
      end
    end
  end
  
  # @!method get_impact(severity)
  #   Takes in the STIG severity tag and converts it to the InSpec #{impact}
  #   control tag.
  #   At the moment the mapping is static, so that:
  #     high => 0.7
  #     medium => 0.5
  #     low => 0.3
  # @param severity [String] the string value you want to map to an InSpec
  # 'impact' level.
  #
  # @return impact [Float] the impact level level mapped to the XCCDF severity
  # mapped to a float between 0.0 - 1.0.
  #
  # @todo Allow for the user to pass in a hash for the desired mapping of text
  # values to numbers or to override our hard coded values.
  #
  def get_impact(severity)
    impact = case severity
             when 'low' then 0.3
             when 'medium' then 0.5
             else 0.7
             end
    impact
  end
end