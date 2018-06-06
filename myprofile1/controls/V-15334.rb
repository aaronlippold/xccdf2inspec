control "V-15334" do
  title "Web sites must utilize ports, protocols, and services according to
PPSM guidelines."
  desc  "Failure to comply with DoD ports, protocols, and services (PPS)
requirements can result
    in compromise of enclave boundary protections and/or functionality of the
AIS.

    The IAM will ensure web servers are configured to use only authorized PPS
in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1,
Ports, Protocols, and Services Management (PPSM), and the associated Ports,
Protocols, and Services (PPS) Assurance Category Assignments List.

  "
  impact 0.3
  tag "gtitle": "WG610"
  tag "gid": "V-15334"
  tag "rid": "SV-34015r1_rule"
  tag "stig_id": "WG610 A22"
  tag "fix_id": "F-26863r1_fix"
  tag "cci": []
  tag "nist": ["CM-7(3)", "Rev_4"]
  tag "documentable": false
  tag "responsibility": "Information Assurance Officer"
  tag "diacap": ["DCPP-1"]
  tag "check": "Review the web site to determine if HTTP and HTTPs are used in
accordance with well known ports (e.g., 80 and 443) or those ports and services
as registered and approved for use by the DoD PPSM. Any variation in PPS will
be documented, registered, and approved by the PPSM. If not, this is a finding."
  tag "fix": "Ensure the web site enforces the use of IANA well-known ports for
HTTP and HTTPS."
end

