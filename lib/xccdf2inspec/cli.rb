#!/usr/bin/env ruby
# encoding: utf-8
# author: Aaron Lippold
# author: Rony Xavier rx294@nyu.edu

require "thor"
require 'nokogiri'
require_relative 'version'
require_relative 'xccdf2inspec'

# DTD_PATH = "checklist.dtd"

class MyCLI < Thor
  desc 'exec', 'xccdf2inspec translates an xccdf file to an inspec profile'
  option :xccdf, required: true, aliases: '-x'
  option :cci, require: true, aliases: '-c'
  option :output, required: false, aliases: '-o'
  option :format, required: false, aliases: '-f'
  option :seperate_files, required: false, aliases: '-s'
  
  def exec
    Xccdf2Inspec.new(options[:xccdf], options[:cci], options[:output], options[:format], options[:seperate_files])
  end

  map %w{--help -h} => :help
  desc 'help', 'Help for using Inspec2ckl'
  def help
    puts "\nXCCDF2Inspec translates an xccdf file to an inspec profile\n\n"
    puts "\t-x --xccdf : Path to the disa stig xccdf file"
    puts "\t-c --cci : Path to the cci xml file"
    puts "\t-o --output : The name of the inspec file you want"
    puts "\t-f --format [ruby | hash] : The format you would like (defualt: ruby)"
    puts "\t-s --seperate-files [true | false] : The format you would like (defualt: ruby)"
    puts "\nexample: ./xccdf2inspec exec -c cci_list.xml -x xccdf_file.xml -o myprofile -f ruby \n\n"
  end

  map %w{--version -v} => :print_version
  desc '--version, -v', "print's inspec2ckl version"
  def print_version
    puts XCCDF2InSpec::VERSION
  end
end

MyCLI.start(ARGV)