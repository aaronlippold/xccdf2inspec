control "V-2254" do
  title "Only web sites that have been fully reviewed and tested must exist on
a production web server."
  desc  "In the case of a production web server, areas for content development
and testing will not exist, as this type of content is only permissible on a
development web site. The process of developing on a functional production web
site entails a degree of trial and error and repeated testing. This process is
often accomplished in an environment where debugging, sequencing, and
formatting of content are the main goals. The opportunity for a malicious user
to obtain files that reveal business logic and login schemes is high in this
situation. The existence of such immature content on a web server represents a
significant security risk that is totally avoidable."
  impact 0.5
  tag "gtitle": "WG260"
  tag "gid": "V-2254"
  tag "rid": "SV-32830r2_rule"
  tag "stig_id": "WG260 A22"
  tag "fix_id": "F-29340r1_fix"
  tag "cci": []
  tag "nist": ["CM-6", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECSC-1"]
  tag "check": "Query the ISSO, the SA, and the web administrator to find out
if development web sites are being housed on production web servers.

Proposed Questions:
Do you have development sites on your production web server?
What is your process to get development web sites / content posted to the
production server?
Do you use under construction notices on production web pages?

The reviewer can also do a manual check or perform a navigation of the web site
via a browser could be used to confirm the information provided from
interviewing the web staff. Graphics or texts which proclaim Under Construction
or Under Development are frequently used to mark folders or directories in that
status.

If Under Construction or Under Development web content is discovered on the
production web server, this is a finding."
  tag "fix": "The presences of portions of the web site that proclaim Under
Construction or Under Development are clear indications that a production web
server is being used for development. The web administrator will ensure that
all pages that are in development are not installed on a production web server."
end

