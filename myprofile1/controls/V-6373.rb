control "V-6373" do
  title "The required DoD banner page must be displayed to authenticated users
accessing a DoD private website."
  desc  "A consent banner will be in place to make prospective entrants aware
that the website they are about to enter is a DoD web site and their activity
is subject to monitoring. The document, DoDI 8500.01, establishes the policy on
the use of DoD information systems. It requires the use of a standard Notice
and Consent Banner and standard text to be included in user agreements. The
requirement for the banner is for websites with security and access controls.
These are restricted and not publicly accessible. If the website does not
require authentication/authorization for use, then the banner does not need to
be present. A manual check of the document root directory for a banner page
file (such as banner.html) or navigation to the website via a browser can be
used to confirm the information provided from interviewing the web staff."
  impact 0.3
  tag "gtitle": "WG265"
  tag "gid": "V-6373"
  tag "rid": "SV-33026r2_rule"
  tag "stig_id": "WG265 A22"
  tag "fix_id": "F-29341r2_fix"
  tag "cci": []
  tag "nist": ["AC-8", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECWM-1"]
  tag "check": "The document, DoDI 8500.01, establishes the policy on the use
of DoD information systems. It requires the use of a standard Notice and
Consent Banner and standard text to be included in user agreements.

The requirement for the banner is for websites with security and access
controls. These are restricted and not publicly accessible. If the website does
not require authentication/authorization for use, then the banner does not need
to be present.

If a banner is required, the following banner page must be in place:

“You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent
to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

- At any time, the USG may inspect and seize data stored on this IS.

- Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.

- This IS includes security measures (e.g., authentication and access controls)
to protect USG interests—not for your personal benefit or privacy.

- Notwithstanding the above, using this IS does not constitute consent to PM,
LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.”

OR

If your system cannot meet the character limits to store this amount of text in
the banner, the following is another option for the warning banner:

\"I've read & consent to terms in IS user agreem't.\"

NOTE: While DoDI 8500.01 does not contain a copy of the banner to be used, it
does point to the RMF Knowledge Service for a copy of the required text.  It is
also noted that the banner is to be displayed only once when the individual
enters the site and not for each page.

If the access-controlled website does not display this banner page before
entry, this is a finding."
  tag "fix": "Configure a DoD private website to display the required DoD
banner page when authentication is required for user access."
end

