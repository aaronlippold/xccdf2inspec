control "V-13689" do
  title "Access to the web server log files must be restricted to
administrators, web administrators, and auditors."
  desc  "A major tool in exploring the web site use, attempted use, unusual
conditions, and problems are the access and error logs. In the event of a
security incident, these logs can provide the SA and the web administrator with
valuable information. Because of the information that is captured in the logs,
it is critical that only authorized individuals have access to the logs."
  impact 0.5
  tag "gtitle": "WG255"
  tag "gid": "V-13689"
  tag "rid": "SV-36643r1_rule"
  tag "stig_id": "WG255 A22"
  tag "fix_id": "F-26859r1_fix"
  tag "cci": []
  tag "nist": ["AU-9", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "diacap": ["ECTP-1"]
  tag "check": "Look for the presence of log files at:

/usr/local/apache/logs/access_log

To ensure the correct location of the log files, examine the \"ServerRoot\"
directive in the htttpd.conf file and then navigate to that directory where you
will find a subdirectory for the logs.

Determine permissions for log files, from the command line: cd to the directory
where the log files are located and enter the command:

ls –al *log and note the owner and group permissions on these files. Only the
Auditors, Web Managers, Administrators, and the account that runs the web
server should have permissions to the files.

If any users other than those authorized have read access to the log files,
this is a finding.
"
  tag "fix": "To ensure the integrity of the data that is being captured in the
log files, ensure that only the members of the Auditors group, Administrators,
and the user assigned to run the web server software is granted permissions to
read the log files."
end

