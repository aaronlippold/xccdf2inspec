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
  def initialize(xccdf_path, cci_path)
    @cci_xml = File.read(cci_path)
    @xccdf_xml = File.read(xccdf_path)
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
      control.impact = group.rule.severity
      control.add_tag(Inspec::Tag.new('severity', group.rule.severity))
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
    Dir.mkdir 'controls' unless Dir.exist?('controls')
    @controls.each do |control|
      file_name = control.id.to_s
      myfile = File.new("controls/#{file_name}.rb", 'w')
      width = 80
      myfile.puts wrap(control.to_ruby)
      myfile.close
    end
  end
end