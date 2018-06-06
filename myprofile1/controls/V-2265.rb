control "V-2265" do
  title "Java software on production web servers must be limited to class files
and the JAVA virtual machine."
  desc  "From the source code in a .java or a .jpp file, the Java compiler
produces a binary file with an extension of .class. The .java or .jpp file
would, therefore, reveal sensitive information regarding an application’s logic
and permissions to resources on the server. By contrast, the .class file,
because it is intended to be machine independent, is referred to as bytecode.
Bytecodes are run by the Java Virtual Machine (JVM), or the Java Runtime
Environment (JRE), via a browser configured to permit Java code."
  impact 0.3
  tag "gtitle": "WG490"
  tag "gid": "V-2265"
  tag "rid": "SV-33032r1_rule"
  tag "stig_id": "WG490 A22"
  tag "fix_id": "F-29347r1_fix"
  tag "cci": []
  tag "nist": ["CM-6", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "diacap": ["ECSC-1"]
  tag "check": "Enter the commands:

find / -name *.java

find / -name *.jpp

If either file type is found, this is a finding."
  tag "fix": "Remove the unnecessary files from the web server."
end

