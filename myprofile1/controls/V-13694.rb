control "V-13694" do
  title "Public web servers must use TLS if authentication is required."
  desc  "Transport Layer Security (TLS) is optional for a public web server.
However, if authentication is being performed, then the use of the TLS protocol
is required.

    Without the use of TLS, the authentication data would be transmitted
unencrypted and would become vulnerable to disclosure.  Using TLS along with
DoD PKI certificates for encryption of the authentication data protects the
information from being accessed by all parties on the network.  To further
protect the authentication data, the web server must use a FIPS 140-2 approved
TLS version and all non-FIPS-approved SSL versions must be disabled.

    FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP
800-52 specifies the preferred configurations for government systems.

  "
  impact 0.5
  tag "gtitle": "WG342"
  tag "gid": "V-13694"
  tag "rid": "SV-33030r2_rule"
  tag "stig_id": "WG342 A22"
  tag "fix_id": "F-29345r2_fix"
  tag "cci": []
  tag "nist": ["AC-17(2)", "AC-18(1)", "SC-9", "SC-9(1)", "SC-13", "SC-13(1)",
"SC-13(2)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECCT-1", "ECCT-2"]
  tag "check": "Enter the following command:

/usr/local/apache2/bin/httpd –M

This will provide a list of all the loaded modules. Verify that the
“ssl_module” is loaded. If this module is not found, this is a finding.

After determining that the ssl module is active, enter the following command:

grep \"SSL\" /usr/local/apache2/conf/httpd.conf

Review the SSL sections of the httpd.conf file, all enabled SSLProtocol
directives for Apache 2.2.22 and older must be set to “TLSv1”.  Releases newer
than Apache 2.2.22 must be set to \"ALL -SSLv2 -SSLv3\". If SSLProtocol is not
set to the proper value, this is a finding.

All enabled SSLEngine directives must be set to “on”, If they are not, this a
finding.

NOTE: In some cases web servers are configured in an environment to support
load balancing. This configuration most likely utilizes a content switch to
control traffic to the various web servers. In this situation, the TLS
certificate for the web sites may be installed on the content switch vs. the
individual web sites. This solution is acceptable as long as the web servers
are isolated from the general population LAN. Users should not have the ability
to bypass the content switch to access the web sites.
"
  tag "fix": "Edit the httpd.conf file and set the SSLProtocol to \"TLSv1\" for
Apache 2.2.22 and older or to \"ALL -SSLv2 -SSLv3\" for Apache versions newer
than 2.2.22.  The SSLEngine parameter must also be set to On."
end

