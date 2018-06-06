control "V-13686" do
  title "Web Administrators must only use encrypted connections for Document
Root directory uploads."
  desc  "Logging in to a web server via an unencrypted protocol or service, to
upload documents to the web site, is a risk if proper encryption is not
utilized to protect the data being transmitted.  An encrypted protocol or
service must be used for remote access to web administration tasks."
  impact 0.7
  tag "gtitle": "WG235"
  tag "gid": "V-13686"
  tag "rid": "SV-33024r1_rule"
  tag "stig_id": "WG235 A22"
  tag "fix_id": "F-29338r1_fix"
  tag "cci": []
  tag "nist": ["AC-17", "AC-17(2)", "AC-17(3)", "AC-17(4)", "AC-17(7)", "MA-4",
"MA-4(1)", "MA-4(6)", "IA-2(2)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["EBRP-1", "EBRU-1"]
  tag "check": "Determine if there is a process for the uploading of files to
the web site. This process should include the requirement for the use of a
secure encrypted logon and secure encrypted connection. If the remote users are
uploading files without utilizing approved encryption methods, this is a
finding."
  tag "fix": "Use only secure encrypted logons and connections for uploading
files to the web site."
end

