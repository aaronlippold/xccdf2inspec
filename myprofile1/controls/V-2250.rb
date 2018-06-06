control "V-2250" do
  title "Logs of web server access and errors must be established and
maintained"
  desc  "A major tool in exploring the web site use, attempted use, unusual
conditions, and problems are reported in the access and error logs. In the
event of a security incident, these logs can provide the SA and the web manager
with valuable information. Without these log files, SAs and web managers are
seriously hindered in their efforts to respond appropriately to suspicious or
criminal actions targeted at the web site."
  impact 0.5
  tag "gtitle": "WG240"
  tag "gid": "V-2250"
  tag "rid": "SV-33025r1_rule"
  tag "stig_id": "WG240 A22"
  tag "fix_id": "F-29339r1_fix"
  tag "cci": []
  tag "nist": ["AU-6", "AU-6(1)", "AU-6(3)", "AU-12", "IR-4(5)", "SI-4(12)",
"Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECAT-1", "ECAT-2"]
  tag "check": "To view a list of loaded modules enter the following command:

/usr/local/apache2/bin/httpd -M

If the following module is not found, this is a finding: \"log_config_module\""
  tag "fix": "Edit the httpd.conf file and add the following module to
configure logging.

\"log_config_module\""
end

