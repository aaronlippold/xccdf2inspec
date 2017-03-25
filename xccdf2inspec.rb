#!/usr/local/bin/ruby
gem 'inspec','>=1.17.0'
require 'inspec'
require 'nokogiri'
require 'optparse'
require 'inspec/objects'
script_version = 1.0
# @version 1.0
# @author Aaron Lippold, lippold@gmail.com
# @author Michael Limiero
# @abstract XCCDF to InSpec Stubs Parser
#   The XCCDF to InSpec Parser scans and extracts the Controls defined in the
#   DISA XCCDF STIG XML documents and converts them into InSpec controls to
#   help make writting InSpec profiles based on the controls defined in DISA
#   STIG documents. The parser requires two files:
#     1. The XCCDF XML file - http://iase.disa.mil/stigs/Pages/a-z.aspx
#     2. the CCI XML file
#       a. Info: http://iase.disa.mil/stigs/cci/Pages/index.aspx
#       b. File: http://iasecontent.disa.mil/stigs/zip/u_cci_list.zip
#
# @todo add support to pass in two elements, ideally, the ability to:
#   a) take in the input files as command line references to the files such as:
#     - repo, http, local file, etc.
#   b) if no files are provided - espically the CCI - be able to:
#     1. Tell the user to provide a CCI file by local or remote reference
#     2. Go see if it can download the CCI xml file, unzip it and use
#     3. Ask if we just want to SKIP the NIST control mapping, or quit
#     4. If neither file is provided, we could query the DISA STIG sight and
#        provide the user a choice as to which stig they would like to process.
#   c) provide the expected command line flags to the script for inputs, outputs,
#      etc.
#
#
# @options asldkfjasldkfjlaksdjf
#
options = {
  xccdf: nil,
  cci: nil,
  output: nil,
  group: nil,
  form: nil
}

parser = OptionParser.new do |opts|
  opts.banner = 'Usage: xccdf2inspec.rb [options]'
  opts.on('-x', '--xccdf xccdf', 'the path to the disa stig xccdf file') do |xccdf|
    options[:xccdf] = xccdf
  end

  opts.on('-c', '--cci cci', 'the path to the cci xml file') do |cci|
    options[:cci] = cci
  end

  opts.on('-g', '--group group1,group2,group3', 'A CSV list of the group you want to process
	in the XCCDF file') do |group|
   options[:group] = group
 end

  opts.on('-o', '--output output.rb', 'The name of the inspec file you want') do |output|
    options[:output] = output
  end

  opts.on('-f', '--format [ruby|hash]', 'The format you would like (defualt: ruby)') do |form|
    options[:form] = form
  end

  opts.on('-v', '--version', 'xccdf2inspec version') do
    puts 'xccdf2inspec: version ' + script_version.to_s
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
out = if options[:output]
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

# @!method get_nist_reference(cci_xml_file, cci_number)
#   Finds the most recent NIST 800-53 Control Identifier linked to the
#   #{cci_number}
# @param [FileHandle] cci_xml_file the open file handle of the disa cci xml
# @param [String] cci_number the CCI number you are using to query the xml
#
# @return [Array<String>, nil] an array containing the CCI Control Number and
#   the version of the NIST 800-53 Revision the Control identifer is published
#   in.
# @todo account for the case when we don't find the CCI passed in, we should
#   return nil. i.e. use the {#status} var.
# @todo this needs to be refactored. It works if there is only one <ident>
#   node in the nodeSet, It does not actually account for the fact that the
#   opbject that are being passed to it could have more than one element.
#   Specicically that cci_number is a nodeSet and needs to be looped over to
#   pull all the CCI numbers then the mapping needs to happen.
def get_nist_reference(cci_file, cci_number)
  nist_ref = nil
  nist_ver = nil
  item_node = cci_file.xpath("//cci_list/cci_items/cci_item[@id='#{cci_number}']")[0]
  nist_ref = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@index').text
  nist_ver = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@version').text
  [nist_ref, nist_ver]
end

# @!method get_impact(severity)
#   Takes in the STIG severity tag and converts it to the InSpec #{impact}
#   control tag.
#   At the moment the mapping is static, so that:
#     high => 0.7
#     medium => 0.5
#     low => 0.3
# @param [String] cci_number the CCI number you are using to query the xml
#
# @return [Float] The impact value as mapped above see: above
#
# @todo Allow for the user to pass in a hash for the desired mapping of text
#   values to numbers or to override our hard coded values.
#
def get_impact(severity)
  impact = nil
  impact = case severity
           when 'low' then 0.3
           when 'medium' then 0.5
           else 0.7
  end
  impact
end

# @!method get_nist_reference(cci_xml_file, cci_number,group)
#   Finds the most recent NIST 800-53 Control Identifier linked to the
#   {#cci_number}
# @param [FileHandle] cci_xml_file the open file handle of the disa cci xml
# @param [String] cci_number the CCI number you are using to query the xml
#
# @return [Array<String>, nil] an array containing the CCI Control Number and
#   the reversion of the NIST 800-53 Revision the Control identifer is published
#   in.
# @todo account for the case when we don't find the CCI passed in, we should
#   return nil.
#
def xccdf_to_inspec(file, cci_file, group, out, output_format)
  # @todo hash for the inspec control objects
  # key is the value of the control_name
  # controls = Hash.new { |hash, key| hash[key] = {} }
  # @todo we need to add the ref item to the inspec control object.

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

  file.xpath(benchmark_xpath).each do |node|
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
    node.xpath('./Rule/ident').each do |cci_node|
      nist, nist_rev = get_nist_reference(cci_file, cci_node.text)
      control.add_tag(Inspec::Tag.new('cci', cci_node.text))
      control.add_tag(Inspec::Tag.new('nist', [nist, 'Rev_' + nist_rev]))
    end
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
    # control.add_newline (nice to have @chris-rock)
    # control.ref = my reference tags
    # control.add_newline (nice to have @chris-rock)
    # @todo control.add_footer (nice to have @chris-rock)
    # the idea is that it would append the default:
    # 	describe ' ' do" + "\n\n"
    # 	end" + "\n\n"
    # before the final 'end' of each control

    if output_format == 'hash'
      out.puts control.to_hash
    else
      out.puts control.to_ruby
      # @todo not sure how to hack the object to add on the stub blocks
      # out.puts "  describe ' ' do" + "\n\n"
      # out.puts "  end" + "\n\n"
    end
  end
end

xccdf_to_inspec(xccdf, cci_xml, options[:group], out, output_format)
out.close if options[:output]
