#!/usr/local/bin/ruby
require 'nokogiri'
require 'optparse'
require 'hashie'
# require 'inspec/lib/control.rb'

#
# @author Aaron Lippold, lippold@gmail.com
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
options = {:xccdf => nil, :cci => nil}

parser = OptionParser.new do|opts|
	opts.banner = "Usage: xccdf2inspec.rb [options]"
	opts.on('-x', '--xccdf xccdf', 'the path to the disa stig xccdf file') do |xccdf|
		options[:xccdf] = xccdf;
	end

	opts.on('-c', '--cci cci', 'the path to the cci xml file') do |cci|
		options[:cci] = cci;
	end

  opts.on('-o', '--output output.rb', 'The name of the inspec file you want') do |output|
    options[:output] = output;
  end

	opts.on('-h', '--help', 'Displays Help') do
		puts opts
		exit
	end
end

parser.parse!

if options[:xccdf] == nil
	print 'Enter the path to your XCCDF file: '
    options[:xccdf] = gets.chomp
end

if options[:cci] == nil
	print 'Enter the path to your CCI file: '
    options[:cci] = gets.chomp
end

if options[:output] == nil
	print 'Your controls are in ./inspec.rb '
end

xccdf_file = options[:xccdf].to_s
cci_file = options[:cci].to_s

cci_xml = Nokogiri::XML(File.open(cci_file))
xccdf = Nokogiri::XML(File.open(xccdf_file))
cci_xml.remove_namespaces!
xccdf.remove_namespaces!

# output = inSpec control object

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
  #
  def get_nist_reference(cci_xml_file,cci_number)
    nist_ref = nil
    nist_ver = nil
    status = nil
    cci_xml_file.xpath('//cci_list/cci_items/cci_item').each do |item_nodes|
      curr_id = item_nodes.xpath('./@id').text
      status = case curr_id
        when cci_number then
          status = "found"
          nist_ref = item_nodes.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@index').text
          nist_ver = item_nodes.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@version').text
      end
    end
    return nist_ref,nist_ver
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
    return impact
  end

  # @!method get_nist_reference(cci_xml_file, cci_number)
  #   Finds the most recent NIST 800-53 Control Identifier linked to the
  #   {#cci_number}
  # @param [FileHandle] cci_xml_file the open file handle of the disa cci xml
  # @param [String] cci_number the CCI number you are using to query the xml
  #
  # @return [Array<String>, nil] an array containing the CCI Control Number and
  #   the version of the NIST 800-53 Revision the Control identifer is published
  #   in.
  # @todo account for the case when we don't find the CCI passed in, we should
  #   return nil.
  # @todo This should return a hash
  #
  def xccdf_to_inspec(file,cci_file)

	# @todo hash for the inspec control objects
	# key is the value of the control_name
	# controls = Hash.new { |hash, key| hash[key] = {} }

	# @todo the inspec control object for this itteration
	# curr_control = new inspec.control()

    file.xpath('//Benchmark/Group').each do |node|
      control_name = node.xpath('./@id').text
      severity = node.xpath('./Rule/@severity').text
      impact = get_impact(severity)
      group_title = node.xpath('./title').text
      group_id = node.xpath('./@id').text
      rule_id = node.xpath('./Rule/@id').text
      stig_id = node.xpath('./Rule/version').text
      cci = node.xpath('./Rule/ident').text
      nist = get_nist_reference(cci_file,cci)
      control_title = node.xpath('./Rule/title').text
      control_desc = node.xpath('./Rule/description').text.gsub(/\<.*?\>/, '')
      check = node.xpath('./Reule/check/check-content').text
      fix = node.xpath('./Rule/fixtext').text

      puts control_name
      puts severity
      puts impact
      puts group_title
      puts group_id
      puts rule_id
      puts stig_id
      puts cci
      puts nist.shift
      puts nist.shift
      puts control_title
      puts control_desc
      puts check
      puts fix
  end
  # it should just return a hash of InSpec crontrol objects here ...
end

xccdf_to_inspec(xccdf,cci_xml)

=begin

=== start template ===
  control 'V-68875' do
    # This requires an 'if statment' on the the value of [/Group/Rule/@severity], i.e. mapping the range
    impact 0.5 [/Group/Rule/@severity] @severity{0.3 if 'low'; 0.5 if 'medium' ; 0.8 if 'high'}}
    tag severity: 'medium[/Group/Rule/@severity]'
    {newline}
    tag gtitle: 'SRG-APP-000001-DB-000031[/Group/title/.]'
    tag gid: 'V-68875[/Group/@id]'
    tag rid: 'SV-83479r1_rule[/Group/Rule/@id]'
    tag stigid: 'PPS9-00-000100[/Group/Rule/version/.]'
    {newline}
      # The NIST reference comes from another XML file from DISA, the value is linked to the CCI number
      # and must be extracted from another file.
      # You will note, the references() has more than one child, I am looking for the vlaue of the
      # @index attribute whoes element has the @version value of '4'
      # Note: **There have been cases where there have been more than 1 CCI tag and NIST tag.**
    tag nist: 'AC-10' [U_CCI_List.xml/cci_items/cci_item/references/reference[@version = '4']/@index]
    tag cci: 'CCI-000054'[/Group/Rule/ident/.]
    {newline}
      # This string could be generated off elements in the:
      # [/Benchmark/title] and
      # [/Benchmark/<plain-text id="release-info">/.]
      # [/Benchmark/version/.]
      # U_ would be a static part of the string, as would _STIG.zip and http://iasecontent.disa.mil/stigs/zip/
    ref 'http://iasecontent.disa.mil/stigs/zip/Oct2016[/Benchmark//U_EDB_Postgres_Advanced_Server_V1R2_STIG.zip[xsl paramater I set or pass in?]'
    {newline}
    title 'Limit the number of concurrent sessions to an organization-defined
            number per user for all accounts and/or account types.[/Group/Rule/title/.]'
    {newline}
    # These come from basically the same source, I will have to figure out a way to simplily title vs desc
    desc 'The EDB Postgres Advanced Server must limit the number of concurrent
          sessions to an organization-defined number per user for all accounts
          and/or account types. Note: listed as Rule Title in the document.[/Group/Rule/description/.]'
    {newline}
    tag check:'Determine whether the system documentation specifies limits on the
              number of concurrent DBMS sessions per account by type of user. If
              it does not, assume a limit of 10 for database administrators and 2
              for all other users. Execute the following SQL as enterprisedb:

              SELECT rolname, rolconnlimit FROM pg_roles;

              If rolconnlimit is -1 or larger than the system documentation limits
              for any rolname, this is a finding.[/Group/Rule/check/check-content/.]'
    {newline}
    tag fix: 'Execute the following SQL as enterprisedb:

              SELECT rolname, rolconnlimit FROM pg_roles;

              For any roles where rolconnlimit is -1 or larger than the system
              documentation limits, execute this SQL as enterprisedb:

              ALTER USER <role> WITH CONNECTION LIMIT <desired connection limit>[/Group/Rule/fixtext/.]'
    {newline}
    describe ' ' do
    end
  end
  === end template ===
=end
