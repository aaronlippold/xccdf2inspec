control "V-13688" do
  title "Log file data must contain required data elements."
  desc  "The use of log files is a critical component of the operation of the
Information Systems (IS) used within the DoD, and they can provide invaluable
assistance with regard to damage assessment, causation, and the recovery of
both affected components and data. They may be used to monitor accidental or
intentional misuse of the (IS) and may be used by law enforcement for criminal
prosecutions. The use of log files is a requirement within the DoD."
  impact 0.5
  tag "gtitle": "WG242"
  tag "gid": "V-13688"
  tag "rid": "SV-36642r1_rule"
  tag "stig_id": "WG242 A22"
  tag "fix_id": "F-13116r1_fix"
  tag "cci": []
  tag "nist": ["AU-2", "AU-3", "AU-8", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "diacap": ["ECAR-1", "ECAR-2", "ECAR-3"]
  tag "check": "To verify the log settings:

Default UNIX location: /usr/local/apache/logs/access_log

If this directory does not exist, you can search the web server for the
httpd.conf file to determine the location of the logs.

Items to be logged are as shown in this sample line in the httpd.conf file:

LogFormat \"%a %A %h %H %l %m %s %t %u %U \\\"%{Referer}i\\\" \" combined

If the web server is not configured to capture the required audit events for
all sites and virtual directories, this is a finding."
  tag "fix": "Configure the web server to ensure the log file data includes the
required data elements."
end

