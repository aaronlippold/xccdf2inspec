control "V-6531" do
  title "Private web servers must require certificates issued from a
DoD-authorized Certificate Authority."
  desc  "Web sites requiring authentication within the DoD must utilize PKI as
an authentication mechanism for web users. Information systems residing behind
web servers requiring authorization based on individual identity must use the
identity provided by certificate-based authentication to support access control
decisions."
  impact 0.5
  tag "gtitle": "WG140"
  tag "gid": "V-6531"
  tag "rid": "SV-33019r1_rule"
  tag "stig_id": "WG140 A22"
  tag "fix_id": "F-29335r1_fix"
  tag "cci": []
  tag "nist": ["IA-5(2)", "SC-12(4)", "SC-12(5)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["IATS-1", "IATS-2"]
  tag "check": "To view the SSLVerifyClient value enter the following command:

grep \"SSLVerifyClient\" /usr/local/apache2/conf/httpd.conf.

If the value of SSLVerifyClient is not set to “require”, this is a finding."
  tag "fix": "Edit the httpd.conf file and set the value of SSLVerifyClient to
\"require\"."
end

