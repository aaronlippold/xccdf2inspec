#!/usr/local/bin/ruby

require 'nokogiri'
require 'optparse'
require 'inspec/objects'
require 'fileutils'
require 'open-uri'
script_version = '1.3.0'

# @author Aaron Lippold, lippold@gmail.com
# @contributor Michael Limiero
# @abstract XCCDF to InSpec Stubs Parser
#   The XCCDF to InSpec Parser scans and extracts the Controls defined in the
#   DISA XCCDF STIG XML documents and converts them into InSpec control 'stubs'
#   to help make writting InSpec profiles easier.
#
#   The parser requires two files:
#     1. The XCCDF XML file - http://iase.disa.mil/stigs/Pages/a-z.aspx
#     2. the CCI XML file
#       a. Info: http://iase.disa.mil/stigs/cci/Pages/index.aspx
#       b. File: http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip
#
# @todo add support to pass in two elements, ideally, the ability to:
#   @todo a) take in the input files as command line references to the files
#   such as: repo, http, local file, etc.
#   @todo b) if no files are provided - espically the CCI - be able to:
#     1. Tell the user to provide a CCI file by local or remote reference
#     2. Go see if it can download the CCI xml file, unzip it and use
#     3. Ask if we just want to SKIP the NIST control mapping, or quit
#     4. If neither file is provided, we could query the DISA STIG sight and
#        provide the user a choice as to which stig they would like to process.
#   @todo c) provide the expected command line flags to the script for inputs,
#    outputs, etc.
#

ARGV << '-h' if ARGV.empty?

options = {
  xccdf: nil,
  cci: nil,
  output: nil,
  group: nil,
  form: nil,
  seperate: nil
}

parser = OptionParser.new do |opts|
  opts.banner = 'Usage: xccdf2inspec.rb [options]'
  opts.on('-x', '--xccdf xccdf', 'the path to the disa stig xccdf file') do |xccdf|
    options[:xccdf] = xccdf
  end

  opts.on('-c', '--cci cci', 'the path to the cci xml file') do |cci|
    options[:cci] = cci
  end

  opts.on(
    '-g',
    '--group group1,group2,group3',
    'A CSV list of the controls - i.e. groups (V-#####) - you want to process') do |group|
   options[:group] = group
  end

  opts.on('-o', '--output output.rb', 'The name of the inspec file you want') do |output|
    options[:output] = output
  end

  opts.on('-f', '--format [ruby|hash]', 'The format you would like (defualt: ruby)') do |form|
    options[:form] = form
  end

  opts.on(
    '-s',
    '--seperate [true|false]',
    'If you want to break the controls into seperate files (defualt: false)') do |seperate|
    options[:seperate] = seperate
  end

  opts.on('-v', '--version', 'xccdf2inspec version') do
    puts 'xccdf2inspec: v' + script_version.to_s
    exit
  end

  opts.on('-h', '--help', 'Displays Help') do
    puts opts
    exit
  end
end

parser.parse!

if options[:xccdf].nil?
  print 'Enter the path to your XCCDF file: '
  options[:xccdf] = gets.chomp
end

if options[:cci].nil?
  print 'Enter the path to your CCI file: '
  options[:cci] = gets.chomp
end

# File output, either the file passed to the -o option, or to $stdout
out = if options[:output] && options[:seperate] != 'true'
        File.open(options[:output], 'w')
      else
        $stdout
      end

xccdf_file = options[:xccdf].to_s
cci_file = options[:cci].to_s

cci_xml = Nokogiri::XML(File.open(cci_file))
cci_xml.remove_namespaces!
xccdf = Nokogiri::XML(File.open(xccdf_file))
xccdf.remove_namespaces!

output_format = options[:form].to_s
seperate_files = options[:seperate].to_s
seperate_files = 'false' unless seperate_files == 'true'


# @!method reformat_wrapped(string,width)
# Reformats a given string to a defined word-wrapped width
# {https://goo.gl/MWE3yl}
# @param string [<String>] the string to be wrapped
# @param width [<Integer>] the width that the string will be wrapped to
#
# @return [<String>] the line-wrapped string
def reformat_wrapped(string, width = 78)
  lines = []
  line = ''
  string.split(/\s+/).each do |word|
    if line.size + word.size >= width
      lines << line
      line = word
    elsif line.empty?
      line = word
    else
      line << ' ' << word
    end
  end
  lines << line if line
  lines.join "\n"
  end
  
def check_most_recent_disa_cci
  uri = 'https://iase.disa.mil/stigs/cci/pages/index.aspx'
  # Perform the HTTP GET request, and return the response
  page = Nokogiri::HTML(open(uri))   
  require 'pry'
  binding.pry
  #http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip
end

# @!method get_benchmark_info(xccdf_file)
# Finds the XCCDF Benchmark information and returns a hash of the the title,
# release version,release date,desc,version,publisher,source,href
# @param xccdf_file [FileHandle] the xccdf file you are processing
#
# @return benchmark_info[Hash<String>] a hash of the benchmark title, release
# version and release date.
#
def get_benchmark_info(xccdf_file)
  benchmark_info =
    Hash.new(
      'title' => '',
      'desc' => '',
      'release_date' => '',
      'version' => '',
      'status' => '',
      'publisher' => '',
      'source' => '',
      'href' => ''
    )
  benchmark_info[:title] =
    xccdf_file.xpath('//Benchmark/title').text
  benchmark_info[:desc] =
    xccdf_file.xpath('//Benchmark/description').text
  benchmark_info[:version] =
    xccdf_file.xpath('//Benchmark/version').text
  benchmark_info[:release_date] =
    xccdf_file.xpath('//Benchmark/status/@date').text
  benchmark_info[:status] =
    xccdf_file.xpath('//Benchmark/status').text
  benchmark_info[:publisher] =
    xccdf_file.xpath('//Benchmark/reference/publisher').text
  benchmark_info[:source] =
    xccdf_file.xpath('//Benchmark/reference/source').text
  benchmark_info[:href] =
    xccdf_file.xpath('//Benchmark/reference/@href').text

  benchmark_info
end

# @!method print_benchmark_info(info)
# calls {#get_benchmark_info}
# Prints XCCDF Benchmark information for easy reading
# @param xccdf [FileHandle] the XCCDF file you want to print info about
#
# @return benchmark_info [String] the string with the formmated info.
#
def print_benchmark_into(xccdf)
  info = get_benchmark_info(xccdf)
  benchmark_info =
    "# encoding: utf-8 \n" \
    "# \n" \
    "=begin \n" \
    "----------------- \n" \
    "Benchmark: #{info[:title]}  \n" \
    "Status: #{info[:status].capitalize} \n\n" +
    reformat_wrapped(info[:desc], width = 78) + "\n\n" \
    "Release Date: #{info[:release_date]} \n" \
    "Version: #{info[:version]} \n" \
    "Publisher: #{info[:publisher]} \n" \
    "Source: #{info[:source]} \n" \
    "uri: #{info[:href]} \n" \
    "----------------- \n" \
    "=end \n\n"

  return benchmark_info
end

# @!method get_nist_reference(cci_file, cci_number)
#   Finds the most recent NIST 800-53 Control Identifier linked to the
#   #{cci_number}
# @param cci_file [FileHandle] the open file handle of the disa cci xml
# @param cci_number [String] the CCI number you are using to query the xml
#
# @return [Array<String>, nil] an array containing the CCI Control Number and
#   the version of the NIST 800-53 Revision the Control identifer is published
#   in.
# @todo account for the case when we don't find the CCI passed in, we should
#   return nil. i.e. use the {#status} var.
#
def get_nist_reference(cci_file, cci_number)
  item_node = cci_file.xpath("//cci_list/cci_items/cci_item[@id='#{cci_number}']")[0]
  nist_ref = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@index').text
  nist_ver = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@version').text
  puts item_node.attributes
  [nist_ref, nist_ver]
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

# @!method xccdf_to_inspec(file, cci_file, group, out, output_format)
# Parses the XCCDF file and generates the inspec control stubs.
# @param file [FileHandle] The XCCDF file you want to parse
# @param cci_file [FileHandle] The CCI XML file
# @param group [String] A csv list of the groups - i.e. controls - you want to
# process from the xccdf file, or 'nil' means you want to process them all.
# @param out [FileHandle] The file that you want to write your output to, if
# 'nil' then it writes to $stdout.
# @param output_format [String] A string that contains either 'ruby' or 'hash'
# and tringgering which 'to_*' method is called in the inspec objects for the
# final output format of the controls.
#
# @return nil [nil] Does not return an object or object references, the method jsut
# prints out to either a file handle or to $stdout
#
# @todo update the method to use the InSpec Profile object when it is written
# @todo update the method to parse out the 'ref' data for the XCCDF document
# @todo update the method to also generate the higher level dirs and xml for
# the profile - i.e. the inspec.yaml file, controls directory etc.
#
def xccdf_to_inspec(xccdf_f, cci_f, group, out, output_format,seperate_files)
  if group.nil?
    benchmark_xpath = '//Benchmark/Group'
  else
    string = '[@id='
    values = group.split(/,/)
    values.each do |v|
      string << if v.equal? values.last
                  "'" + v.to_s + "']"
                else
                  "'" + v.to_s + "'or @id="
                end
    end
    benchmark_xpath = '//Benchmark/Group' + string
  end

  if seperate_files == 'true'
    FileUtils.mkdir_p("./output") unless File.directory?("./output")
    Dir.chdir "./output"
  end

  xccdf_f.xpath(benchmark_xpath).each do |node|
    control = Inspec::Control.new
    control.id = node.xpath('./@id').text
    control.impact = get_impact(node.xpath('./Rule/@severity').text)
    control.add_tag(Inspec::Tag.new('severity', node.xpath('./Rule/@severity').text))
    # control.add_newline (nice to have @chris-rock)
    control.add_tag(Inspec::Tag.new('gtitle', node.xpath('./title').text))
    control.add_tag(Inspec::Tag.new('gid', node.xpath('./@id').text))
    control.add_tag(Inspec::Tag.new('rid', node.xpath('./Rule/@id').text))
    control.add_tag(Inspec::Tag.new('stig_id', node.xpath('./Rule/version').text))
    # control.add_newline (nice to have @chris-rock)
    ccis = []
    nists = []
    nist_rev = ''
    node.xpath('./Rule/ident').each do |cci_node|
      nist, nist_rev = get_nist_reference(cci_f, cci_node.text)
      ccis.push(cci_node.text)
      nists.push(nist)
    end
    control.add_tag(Inspec::Tag.new('cci', ccis))
    control.add_tag(Inspec::Tag.new('nist', nists.push('Rev_' + nist_rev)))
    control.title = node.xpath('./Rule/title').text
    # @todo .gsub(/\<.*?\>/, '') pulls out many of the sub-discussion tags that
    # are in the XCCDF, we need to determine if this is an issue or if - for
    # the most part - this data is unused.
    # @todo gsub(/.false/, '.') pulls off the tailing .false text items that
    # come form the extra metadata < > that the other gsub removes. I am sure
    # there is a more eleagant way to do this but for now it works.
    control.desc = node.xpath('./Rule/description').text.gsub(/\<.*?\>/, '').gsub(/.false/, '.')
    # control.add_newline (nice to have @chris-rock)
    control.add_tag(Inspec::Tag.new('check', node.xpath('./Rule/check/check-content').text))
    # control.add_newline (nice to have @chris-rock)
    control.add_tag(Inspec::Tag.new('fix', node.xpath('./Rule/fixtext').text))
    # @todo control.add_newline (nice to have @chris-rock)
    # @todo control.ref = my reference tags
    # control.add_newline (nice to have @chris-rock)
    # @todo control.add_footer (nice to have @chris-rock)
    # the idea is that it would append the default:
    # 	describe ' ' do" + "\n\n"
    # 	end" + "\n\n"
    # before the final 'end' of each control

    if output_format == 'hash'
      if seperate_files == 'true'
        file_name = node.xpath('./@id').text
        myfile = File.new("#{file_name}.hash","w")
        myfile.puts print_benchmark_into(xccdf_f)
        myfile.puts control.to_hash
        myfile.close
      else
        out.puts control.to_hash
        out.puts "\n"
      end
    else
      if seperate_files == 'true'
        file_name = node.xpath('./@id').text
        myfile = File.new("#{file_name}.rb","w")
        myfile.puts print_benchmark_into(xccdf_f)
        myfile.puts control.to_ruby
        myfile.close
      else
        out.puts control.to_ruby
        out.puts "\n"
      end
    end
  end
end

#check_most_recent_disa_cci

out.puts ":xccdf2inspec: v. #{script_version} \n".prepend("# ") if seperate_files != 'true'
out.puts print_benchmark_into(xccdf) if seperate_files != 'true'
xccdf_to_inspec(xccdf, cci_xml, options[:group], out, output_format,seperate_files)
out.close if options[:output]
