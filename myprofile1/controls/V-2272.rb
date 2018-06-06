control "V-2272" do
  title "PERL scripts must use the TAINT option."
  desc  "PERL (Practical Extraction and Report Language) is an interpreted
language optimized for scanning arbitrary text files, extracting information
from those text files, and printing reports based on that information. The
language is often used in shell scripting and is intended to be practical, easy
to use, and efficient means of generating interactive web pages for the user.
Unfortunately, many widely available freeware PERL programs (scripts) are
extremely insecure. This is most readily accomplished by a malicious user
substituting input to a PERL script during a POST or a GET operation.

    Consequently, the founders of PERL have developed a mechanism named TAINT
that protects the system from malicious input sent from outside the program.
When the data is tainted, it cannot be used in programs or functions such as
eval(), system(), exec(), pipes, or popen(). The script will exit with a
warning message. It is vital that if PERL is being used, the following line
appear in the first line of PERL scripts:

    #!/usr/local/bin/perl –T

  "
  impact 0.5
  tag "gtitle": "WG460"
  tag "gid": "V-2272"
  tag "rid": "SV-6932r1_rule"
  tag "stig_id": "WG460 A22"
  tag "fix_id": "F-2321r1_fix"
  tag "cci": []
  tag "nist": ["CM-6", "Rev_4"]
  tag "documentable": false
  tag "mitigations": ""
  tag "mitigation_controls": "If the TAINT option cannot be used for any
reason, this finding can be mitigated by the use of a third-party input
validation mechanism or input validation will be included as part of the script
in use. This must be documented."
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECSC-1"]
  tag "check": "When a PERL script is invoked for execution on a UNIX server,
the method which invokes the script must utilize the TAINT option.

The server’s interpreter examines the first line of the script. Typically, the
first line of the script contains a reference to the script’s language and
processing options.

The first line of a PERL script will be as follows:

#!/usr/local/bin/perl –T

The –T at the end of the line referenced above, tells the UNIX server to
execute a PERL script using the TAINT option.

Perform the following steps:
1) grep perl httpd.conf |grep -v '#'

You should also check /apache/sysconfig.d/loadmodule.conf for PERL.

NOTE: The name of the loadmodule.conf may vary by installation.

If Apache doesn't have the mod_perl module loaded and it doesn't use PERL, this
check is Not Applicable.

2) grep -i 'PerlTaintCheck' httpd.conf

If 'PerlTaintCheck on' is set, this is not a finding, and the check can stop
here.

NOTE: If the PerlTaintCheck is a part of an included config file, this meets
the requirement.

3) Check each individual PERL script.

From the ServerRoot directory: find . -name '*.pl'
From the DocumentRoot directory: find . -name '*.pl'

Examine the beginning of every PERL script for the -T option. If the -T option
is not specified in any PERL script, this is a finding.

NOTE: This only applies to PERL scripts that are used by the web server.

NOTE: If the mod_perl module is installed and the directive “PerlTaintCheck on”
in the httpd.conf is used, this satisfies the requirement.
"
  tag "fix": "Add the TAINT call to the PERL script.

#!/usr/local/bin/perl –T "
end

