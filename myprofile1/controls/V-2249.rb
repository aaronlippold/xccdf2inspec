control "V-2249" do
  title "Web server administration must be performed over a secure path or at
the local console."
  desc  "Logging into a web server remotely using an unencrypted protocol or
service when performing updates and maintenance is a major risk.  Data, such as
user account, is transmitted in plaintext and can easily be compromised.  When
performing remote administrative tasks, a protocol or service that encrypts the
communication channel must be used.

    An alternative to remote administration of the web server is to perform web
server administration locally at the console.  Local administration at the
console implies physical access to the server.

  "
  impact 0.7
  tag "gtitle": "WG230"
  tag "gid": "V-2249"
  tag "rid": "SV-33023r3_rule"
  tag "stig_id": "WG230 A22"
  tag "fix_id": "F-2298r1_fix"
  tag "cci": []
  tag "nist": ["AC-17", "AC-17(2)", "IA-2(2)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["EBRU-1"]
  tag "check": "If web administration is performed remotely the following
checks will apply:

If administration of the server is performed remotely, it will only be
performed securely by system administrators.

If web site administration or web application administration has been
delegated, those users will be documented and approved by the ISSO.

Remote administration must be in compliance with any requirements contained
within the Unix Server STIGs, and any applicable network STIGs.

Remote administration of any kind will be restricted to documented and
authorized personnel.

All users performing remote administration must be authenticated.

All remote sessions will be encrypted and they will utilize FIPS 140-2 approved
protocols.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater. "
  tag "fix": "Ensure the web server's administration is only performed over a
secure path."
end

