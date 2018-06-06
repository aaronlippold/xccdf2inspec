control "V-2227" do
  title "Symbolic links must not be used in the web content directory tree."
  desc  "A symbolic link allows a file or a directory to be referenced using a
symbolic name raising a potential hazard if symbolic linkage is made to a
sensitive area.

    When web scripts are executed and symbolic links are allowed, the web user
could be allowed to access locations on the web server that are outside the
scope of the web document root or home directory.

  "
  impact 0.7
  tag "gtitle": "WG360"
  tag "gid": "V-2227"
  tag "rid": "SV-30576r1_rule"
  tag "stig_id": "WG360 A22"
  tag "fix_id": "F-26783r1_fix"
  tag "cci": []
  tag "nist": ["SC-2", "CM-6", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If symbolic links are found in the web
content directory tree, the target file or directory is outside of the web
content directory tree, and file permissions allow the web user write
authority, then the severity level will remain at CAT 1.

If symbolic links are found in the web content directory tree, the target file
or directory is outside of the web content directory tree, and file permissions
allow the web user any authority less than write, then the severity level will
be downgraded to CAT 2.

If symbolic links are found in the web content directory tree, the target file
or directory is not outside of the web content directory tree, and file
permissions allow the web user write authority, then the severity level will
remain at CAT 1.

If symbolic links are found in the web content directory tree, the target file
or directory is not outside of the web content directory tree, and file
permissions allow the web user any authority less than write, then the severity
level will be downgraded to CAT 3.
"
  tag "responsibility": "System Administrator"
  tag "diacap": ["DCPA-1", "ECSC-1"]
  tag "check": "Locate the directories containing the web content, (i.e.,
/usr/local/apache/htdocs).

Use ls –al.

An entry, such as the following, would indicate the presence and use of
symbolic links:

lr-xr—r--  4000 wwwusr  wwwgrp\t2345\tApr 15\t  data  ->
/usr/local/apache/htdocs

Such a result found in a web document directory is a finding. Additional Apache
configuration check in the httpd.conf file:

<Directory /[website root dir]>
    Options FollowSymLinks
    AllowOverride None
</Directory>

The above configuration is incorrect and is a finding. The correct
configuration is:

<Directory /[website root dir]>
    Options SymLinksIfOwnerMatch
    AllowOverride None
</Directory>

Finally, the target file or directory must be owned by the same owner as the
link, which should be a privileged account with access to the web content.
"
  tag "fix": "Disable symbolic links."
end

