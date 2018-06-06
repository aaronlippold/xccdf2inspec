control "V-2263" do
  title "A private web server will have a valid DoD server certificate."
  desc  "This check verifies that DoD is a hosted web site's CA. The
certificate is actually a DoD-issued server certificate used by the
organization being reviewed. This is used to verify the authenticity of the web
site to the user. If the certificate is not for the server (Certificate belongs
to), if the certificate is not issued by DoD (Certificate was issued by), or if
the current date is not included in the valid date (Certificate is valid from),
then there is no assurance that the use of the certificate is valid. The entire
purpose of using a certificate is, therefore, compromised."
  impact 0.5
  tag "gtitle": "WG350"
  tag "gid": "V-2263"
  tag "rid": "SV-33031r1_rule"
  tag "stig_id": "WG350 A22"
  tag "fix_id": "F-29346r1_fix"
  tag "cci": []
  tag "nist": ["IA-5(2)", "SC-12(4)", "SC-12(5)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["IATS-1", "IATS-2"]
  tag "check": "Open browser window and browse to the appropriate site. Before
entry to the site, you should be presented with the server's DoD PKI
credentials. Review these credentials for authenticity.

Find an entry which cites:

Issuer:
CN = DOD CLASS 3 CA-3
OU = PKI
OU = DoD
O = U.S. Government
C = US

If the server is running as a public web server, this finding should be Not
Applicable.

NOTE: In some cases, the web servers are configured in an environment to
support load balancing. This configuration most likely utilizes a content
switch to control traffic to the various web servers. In this situation, the
SSL certificate for the web sites may be installed on the content switch vs.
the individual web sites. This solution is acceptable as long as the web
servers are isolated from the general population LAN. Users should not have the
ability to bypass the content switch to access the web sites.
"
  tag "fix": "Configure the private web site to use a valid DoD certificate."
end

