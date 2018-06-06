control "V-2262" do
  title "A private web server must utilize an approved TLS version."
  desc  "Transport Layer Security (TLS) encryption is a required security
setting for a private web server.  Encryption of private information is
essential to ensuring data confidentiality.  If private information is not
encrypted, it can be intercepted and easily read by an unauthorized party.  A
private web server must use a FIPS 140-2 approved TLS version, and all
non-FIPS-approved SSL versions must be disabled.

    FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP
800-52 specifies the preferred configurations for government systems.

  "
  impact 0.5
  tag "gtitle": "WG340"
  tag "gid": "V-2262"
  tag "rid": "SV-33029r2_rule"
  tag "stig_id": "WG340 A22"
  tag "fix_id": "F-29344r2_fix"
  tag "cci": []
  tag "nist": ["CM-6", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECSC-1"]
  tag "check": "Enter the following command:

/usr/local/apache2/bin/httpd –M |grep -i ssl

This will provide a list of all the loaded modules. Verify that the
“ssl_module” is loaded. If this module is not found, determine if it is loaded
as a dynamic module. Enter the following command:

grep ^LoadModule /usr/local/apache2/conf/httpd.conf

If the SSL module is not enabled this is a finding.

After determining that the ssl module is active, enter the following command to
review the SSL directives.

grep -i ssl /usr/local/apache2/conf/httpd.conf

Review the SSL section(s) of the httpd.conf file, all enabled SSLProtocol
directives must be set to “ALL -SSLv2 -SSLv3” or this is a finding.

NOTE: For Apache 2.2.22 and older, all enabled SSLProtocol directives must be
set to \"TLSv1\" or this is a finding.

All enabled SSLEngine directive must be set to “on”, if not this is a finding.

NOTE: In some cases web servers are configured in an environment to support
load balancing. This configuration most likely utilizes a content switch to
control traffic to the various web servers. In this situation, the TLS
certificate for the web sites may be installed on the content switch vs the
individual web sites. This solution is acceptable as long as the web servers
are isolated from the general population LAN. Users should not have the ability
to bypass the content switch to access the web sites.
"
  tag "fix": "Edit the httpd.conf file and set the SSLProtocol to \"ALL -SSLv2
-SSLv3\" and the SSLEngine to On.  For Apache 2.2.22 and older, set SSLProtocol
to \"TLSv1\"."
end

