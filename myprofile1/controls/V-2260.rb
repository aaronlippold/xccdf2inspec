control "V-2260" do
  title "A web site must not contain a robots.txt file."
  desc  "Search engines are constantly at work on the Internet.  Search engines
are augmented by agents, often referred to as spiders or bots, which endeavor
to capture and catalog web-site content.  In turn, these search engines make
the content they obtain and catalog available to any public web user.

    To request that a well behaved search engine not crawl and catalog a site,
the web site may contain a file called robots.txt.  This file contains
directories and files that the web server SA desires not be crawled or
cataloged, but this file can also be used, by an attacker or poorly coded
search engine, as a directory and file index to a site.  This information may
be used to reduce an attacker’s time searching and traversing the web site to
find files that might be relevant.  If information on the web site needs to be
protected from search engines and public view, other methods must be used.

  "
  impact 0.5
  tag "gtitle": "WG310"
  tag "gid": "V-2260"
  tag "rid": "SV-33028r2_rule"
  tag "stig_id": "WG310 A22"
  tag "fix_id": "F-29343r2_fix"
  tag "cci": []
  tag "nist": ["AC-5", "AC-6", "AC-6(2)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECLP-1"]
  tag "check": "Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the
location of the file.

Open the httpd.conf file with an editor and search for the following
uncommented directives: DocumentRoot & Alias

Navigate to the location(s) specified in the Include statement(s), and review
each file for the following uncommented directives: DocumentRoot & Alias

At the top level of the directories identified after the enabled DocumentRoot &
Alias directives, verify that a “robots.txt” file does not exist.  If the file
does exist, this is a finding."
  tag "fix": "Remove the robots.txt file from the web site.  If there is
information on the web site that needs protection from search engines and
public view, then other methods must be used to safeguard the data."
end

