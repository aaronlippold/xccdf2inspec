= Parsing the DISA XCCDF format

You can find all the DISA XCCDF files here:
http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx

The below example shows how the parser maps the values from the XCCDF file to the InSpec control. Should you want to change your 'tag' names, styles etc. please feel free to hack the 'xccdf2inspec' method in the script.

= XCCDF XML to InSpec Control Values
== Example
  control 'V-68875' do
    # This requires an 'if statement' on the the value of [/Group/Rule/@severity], i.e. mapping the range
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
      # You will note, the references() has more than one child, I am looking for the value of the
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

== Old Formatter ( pre InSpec.Control obj use )

#     out.puts "control '" + control_name.to_s + "'" + " do "
# 		out.puts "  impact: " + impact.inspect
# 		out.puts "  tag severity: '" + severity.to_s + "'" + "\n\n"
#     out.puts "  tag gtitle: '" + group_title.to_s + "'"
#     out.puts "  tag gid: '" + group_id.to_s + "'"
#     out.puts "  tag rid: '" + rule_id.to_s + "'"
#     out.puts "  tag stigid: '" + stig_id.to_s + "'" + "\n\n"
#     node.xpath('./Rule/ident').each do |cci_node|
# 	  cci = Inspec::Tag.new("cci",['CCI-','rev'])
#       cci = cci_node.text
#       nist, nist_rev = get_nist_reference(cci_file,cci)
#       out.puts "  tag cci: '" + cci.to_s + "'"
#       out.puts "  tag nist: '" + nist.to_s + "'"
#       out.puts "  tag nist_rev: '" + nist_rev.to_s + "'" + "\n\n"
#     end
#     out.puts "  tag title: '" + control_title.to_s + "' \n\n"
#     out.puts "  tag desc: '" + control_desc.to_s + "' \n\n"
#     out.puts "  tag check: " + check.to_s + "'" + "\n\n"
#     out.puts "  tag fix: '" + fix.to_s + "'" + "\n\n"
# 		out.puts "  describe ' ' do" + "\n\n"
# 		out.puts "  end"
# 		out.puts "end" + "\n\n"
