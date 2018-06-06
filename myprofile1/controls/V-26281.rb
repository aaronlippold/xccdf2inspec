control "V-26281" do
  title "System logging must be enabled."
  desc  "The server error logs are invaluable because they can also be used to
identify potential problems and enable proactive remediation. Log data can
reveal anomalous behavior such as “not found” or “unauthorized” errors that may
be an evidence of attack attempts.   Failure to enable error logging can
significantly reduce the ability of Web Administrators to detect or remediate
problems. The CustomLog directive specifies the log file, syslog facility, or
piped logging utility."
  impact 0.5
  tag "gtitle": "WA00615"
  tag "gid": "V-26281"
  tag "rid": "SV-33206r1_rule"
  tag "stig_id": "WA00615 A22"
  tag "fix_id": "F-29381r1_fix"
  tag "cci": []
  tag "nist": ["AU-2", "AU-3", "AU-8", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECAR-1"]
  tag "check": "Enter the following command:

grep \"CustomLog\" /usr/local/apache2/conf/httpd.conf

The command should return the following value:.

CustomLog \"Logs/access_log\" common

If the above value is not returned, this is a finding.
"
  tag "fix": "Edit the httpd.conf file and enter the name, path and level for
the CustomLog."
end

