control "V-72841" do
  title "PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.\n\nApplications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. \n\nTo support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.\n\nDatabase Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000142-DB-000094"
  tag "gid": "V-72841"
  tag "rid": "SV-87493r1_rule"
  tag "stig_id": "PGS9-00-000100"
  tag "cci": "CCI-000382"
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "cci": "CCI-001762"
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]
  tag "check": "As the database administrator, run the following SQL:\n\n$ psql -c \"SHOW port\"\n\nIf the currently defined port configuration is deemed prohibited, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo change the listening port of the database, as the database administrator, change the following setting in postgresql.conf:\n\n$ sudo su - postgres\n$ vi $PGDATA/postgresql.conf\n\nChange the port parameter to the desired port.\n\nNext, restart the database:\n\n$ sudo su - postgres\n\n# SYSTEMD SERVER ONLY\n$ systemctl restart postgresql-9.5\n\n# INITD SERVER ONLY\n$ service postgresql-9.5 restart\n\nNote: psql uses the default port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable:\n$ psql -p 5432 -c \"SHOW port\"\n$ export PGPORT=5432"
end
control "V-72843" do
  title "PostgreSQL must produce audit records containing sufficient information to establish the outcome (success or failure) of the events."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.\n\nEvent outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000099-DB-000043"
  tag "gid": "V-72843"
  tag "rid": "SV-87495r1_rule"
  tag "stig_id": "PGS9-00-000200"
  tag "cci": "CCI-000134"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs a database administrator (shown here as \"postgres\"), create a table, insert a value, alter the table and update the table by running the following SQL:\n\nCREATE TABLE stig_test(id INT);\nINSERT INTO stig_test(id) VALUES (0);\nALTER TABLE stig_test ADD COLUMN name text;\nUPDATE stig_test SET id = 1 WHERE id = 0;\n\nNext, as a user without access to the stig_test table, run the following SQL:\n\nINSERT INTO stig_test(id) VALUES (1);\nALTER TABLE stig_test DROP COLUMN name;\nUPDATE stig_test SET id = 0 WHERE id = 1;\n\nThe prior SQL should generate errors:\n\nERROR: permission denied for relation stig_test\nERROR: must be owner of relation stig_test\nERROR: permission denied for relation stig_test\n\nNow, as the database administrator, drop the test table by running the following SQL:\n\nDROP TABLE stig_test;\n\nNow verify the errors were logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_logfile>$PGDATA/\n< 2016-02-23 14:51:31.103 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE stig_test(id INT);,<none>\n< 2016-02-23 14:51:44.835 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,2,1,WRITE,INSERT,,,INSERT INTO stig_test(id) VALUES (0);,<none>\n< 2016-02-23 14:53:25.805 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,3,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test ADD COLUMN name text;,<none>\n< 2016-02-23 14:53:54.381 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,4,1,WRITE,UPDATE,,,UPDATE stig_test SET id = 1 WHERE id = 0;,<none>\n< 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >ERROR: permission denied for relation stig_test\n< 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >STATEMENT: INSERT INTO stig_test(id) VALUES (1);\n< 2016-02-23 14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >ERROR: must be owner of relation stig_test\n< 2016-02-23 14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >STATEMENT: ALTER TABLE stig_test DROP COLUMN name;\n< 2016-02-23 14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >ERROR: permission denied for relation stig_test\n< 2016-02-23 14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >STATEMENT: UPDATE stig_test SET id = 0 WHERE id = 1;\n< 2016-02-23 14:55:23.723 EDT psql postgres postgres 570bf307.3b0a 2016-04-11 14:55:03 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,DROP TABLE,,,DROP TABLE stig_test;,<none>\n\nIf audit records exist without the outcome of the event that occurred, this is a finding."
  tag "fix": "Using pgaudit PostgreSQL can be configured to audit various facets of PostgreSQL. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nAll errors, denials and unsuccessful requests are logged if logging is enabled. See supplementary content APPENDIX-C for documentation on enabling logging.\n\nNote: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nWith pgaudit and logging enabled, set the following configuration settings in postgresql.conf, as the database administrator (shown here as \"postgres\"), to the following:\n\n$ vi ${PGDATA?}/postgresql.conf\npgaudit.log_catalog='on'\npgaudit.log_level='log'\npgaudit.log_parameter='on'\npgaudit.log_statement_once='off'\npgaudit.log='all, -misc'\n\nNext, tune the following logging configurations in postgresql.conf:\n\n$ sudo vi ${PGDATA?}/postgresql.conf\nlog_line_prefix = '%m %u %d %e : '\nlog_error_verbosity = default\n\nLast, as the system administrator, restart PostgreSQL:\n\n# SERVER USING SYSTEMCTL ONLY\n$ sudo systemctl restart postgresql-9.5\n\n# SERVER USING INITD ONLY\n$ sudo service postgresql-9.5 restart"
end
control "V-72845" do
  title "Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs)."
  desc  "Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.\n\nOrganization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).\n\nThis requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.\n\nThe application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs)."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000456-DB-000390"
  tag "gid": "V-72845"
  tag "rid": "SV-87497r1_rule"
  tag "stig_id": "PGS9-00-000300"
  tag "cci": "CCI-002605"
  tag "nist": ["SI-2 c", "Rev_4"]
  tag "check": "If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:\n\nTo list the version of installed PostgreSQL using psql:\n\n$ sudo su - postgres\n$ psql -–version\n\nTo list the current version of software for RPM:\n\n$ rpm -qa | grep postgres\n\nTo list the current version of software for APT:\n\n$ apt-cache policy postgres\n\nAll versions of PostgreSQL will be listed on:\n\nhttp://www.postgresql.org/support/versioning/\n\nAll security-relevant software updates for PostgreSQL will be listed on:\n\nhttp://www.postgresql.org/support/security/\n\nIf PostgreSQL is not at the latest version, this is a finding.\n\nIf PostgreSQL is not at the latest version and the evaluated version has CVEs (IAVAs), then this is a CAT I finding."
  tag "fix": "Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed."
end
control "V-72847" do
  title "The audit information produced by PostgreSQL must be protected from unauthorized modification."
  desc  "If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. \n\nTo ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. \n\nThis requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. \n\nApplications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.\n\nAudit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. \n\nModification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000119-DB-000060"
  tag "gid": "V-72847"
  tag "rid": "SV-87499r1_rule"
  tag "stig_id": "PGS9-00-000400"
  tag "cci": "CCI-000163"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Review locations of audit logs, both internal to the database and database audit logs located at the operating system level.\n\nVerify there are appropriate controls and permissions to protect the audit information from unauthorized modification.\n\nNote: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\n#### stderr Logging\n\nIf the PostgreSQL server is configured to use stderr for logging, the logs will be owned by the database owner (usually postgres user) with a default permissions level of 0600. The permissions can be configured in postgresql.conf.\n\nTo check the permissions for log files in postgresql.conf, as the database owner (shown here as \"postgres\"), run the following command:\n\n$ sudo su - postgres\n$ grep \"log_file_mode\" ${PGDATA?}/postgresql.conf\n\nIf the permissions are not 0600, this is a finding.\n\nNext, navigate to where the logs are stored. This can be found by running the following command against postgresql.conf as the database owner (shown here as \"postgres\"):\n\n$ sudo su - postgres\n$ grep \"log_directory\" ${PGDATA?}/postgresql.conf\n\nWith the log directory identified, as the database owner (shown here as \"postgres\"), list the permissions of the logs:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}/pg_log\n\nIf logs are not owned by the database owner (shown here as \"postgres\") and are not the same permissions as configured in postgresql.conf, this is a finding.\n\n#### syslog Logging\n\nIf the PostgreSQL server is configured to use syslog for logging, consult the organizations syslog setting for permissions and ownership of logs."
  tag "fix": "To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nNote: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\n#### stderr Logging\n\nWith stderr logging enabled, as the database owner (shown here as \"postgres\"), set the following parameter in postgresql.conf:\n\n$ vi ${PGDATA?}/postgresql.conf\nlog_file_mode = 0600\n\nTo change the owner and permissions of the log files, run the following:\n\n$ chown postgres:postgres ${PGDATA?}/<log directory name>\n$ chmod 0700 ${PGDATA?}/<log directory name>\n$ chmod 600 ${PGDATA?}/<log directory name>/*.log\n\n#### syslog Logging\n\nIf PostgreSQL is configured to use syslog for logging, the log files must be configured to be owned by root with 0600 permissions.\n\n$ chown root:root <log directory name>/<log_filename>\n$ chmod 0700 <log directory name>\n$ chmod 0600 <log directory name>/*.log"
end
control "V-72849" do
  title "PostgreSQL must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals."
  desc  "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.\n\nA comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. \n\nExamples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.\n\nPostgreSQL must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. \n\nAutomation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000023-DB-000001"
  tag "gid": "V-72849"
  tag "rid": "SV-87501r1_rule"
  tag "stig_id": "PGS9-00-000500"
  tag "cci": "CCI-000015"
  tag "nist": ["AC-2 (1)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nIf all accounts are authenticated by the organization-level authentication/access mechanism, such as LDAP or Kerberos and not by PostgreSQL, this is not a finding.\n\nAs the database administrator (shown here as \"postgres\"), review pg_hba.conf authentication file settings:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_hba.conf\n\nAll records must use an auth-method of gss, sspi, or ldap. For details on the specifics of these authentication methods see: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html\n\nIf there are any records with a different auth-method than gss, sspi, or ldap, review the system documentation for justification and approval of these records.\n\nIf there are any records with a different auth-method than gss, sspi, or ldap, that are not documented and approved, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nIntegrate PostgreSQL security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.\n\nAs the database administrator (shown here as \"postgres\"), edit pg_hba.conf authentication file:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/pg_hba.conf\n\nFor each PostgreSQL-managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate."
end
control "V-72851" do
  title "PostgreSQL must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
  desc  "Any PostgreSQL or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.\n\nDatabases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.\n\nCarefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-DB-000162"
  tag "gid": "V-72851"
  tag "rid": "SV-87503r1_rule"
  tag "stig_id": "PGS9-00-000600"
  tag "cci": "CCI-001312"
  tag "nist": ["SI-11 a", "Rev_4"]
  tag "check": "As the database administrator, run the following SQL:\n\nSELECT current_setting('client_min_messages');\n\nIf client_min_messages is not set to error, this is a finding."
  tag "fix": "As the database administrator, edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi $PGDATA/postgresql.conf\n\nChange the client_min_messages parameter to be error:\n\nclient_min_messages = error\n\nNow reload the server with the new configuration (this just reloads settings currently in memory, will not cause an interruption):\n\n$ sudo su - postgres\n\n# SYSTEMD SERVER ONLY\n$ systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ service postgresql-9.5 reload"
end
control "V-72853" do
  title "Privileges to change PostgreSQL software modules must be limited."
  desc  "If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.\n\nAccordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.\n\nUnmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72853"
  tag "rid": "SV-87505r1_rule"
  tag "stig_id": "PGS9-00-000700"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), check the permissions of configuration files for the database:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}\n\nIf any files are not owned by the database owner or have permissions allowing others to modify (write) configuration files, this is a finding.\n\nAs the server administrator, check the permissions on the shared libraries for PostgreSQL:\n\n$ sudo ls -la /usr/pgsql-9.5\n$ sudo ls -la /usr/pgsql-9.5/bin\n$ sudo ls -la /usr/pgsql-9.5/include\n$ sudo ls -la /usr/pgsql-9.5/lib\n$ sudo ls -la /usr/pgsql-9.5/share\n\nIf any files are not owned by root or have permissions allowing others to modify (write) configuration files, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), change the ownership and permissions of configuration files in PGDATA:\n\n$ sudo su - postgres\n$ chown postgres:postgres ${PGDATA?}/postgresql.conf\n$ chmod 0600 ${PGDATA?}/postgresql.conf\n\nAs the server administrator, change the ownership and permissions of shared objects in /usr/pgsql-9.5/*.so\n\n$ sudo chown root:root /usr/pgsql-9.5/lib/*.so\n$ sudo chmod 0755 /usr/pgsql-9.5/lib/*.so\n\nAs the service administrator, change the ownership and permissions of executables in /usr/pgsql-9.5/bin:\n\n$ sudo chown root:root /usr/pgsql-9.5/bin/*\n$ sudo chmod 0755 /usr/pgsql-9.5/bin/*"
end
control "V-72855" do
  title "PostgreSQL must limit privileges to change functions and triggers, and links to software external to PostgreSQL."
  desc  "If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.\n\nAccordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.\n\nUnmanaged changes that occur to the database code can lead to unauthorized or compromised installations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72855"
  tag "rid": "SV-87507r1_rule"
  tag "stig_id": "PGS9-00-000710"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Only owners of objects can change them. To view all functions, triggers, and trigger procedures, their ownership and source, as the database administrator (shown here as \"postgres\") run the following SQL:\n\n$ sudo su - postgres\n$ psql -x -c \"\\df+\"\n\nOnly the OS database owner user (shown here as \"postgres\") or a PostgreSQL superuser can change links to external software. As the database administrator (shown here as \"postgres\"), check the permissions of configuration files for the database:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}\n\nIf any files are not owned by the database owner or have permissions allowing others to modify (write) configuration files, this is a finding."
  tag "fix": "To change ownership of an object, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su – postgres\n$ psql -c \"ALTER FUNCTION function_name OWNER TO new_role_name\"\n\nTo change ownership of postgresql.conf, as the database administrator (shown here as \"postgres\"), run the following commands:\n\n$ sudo su - postgres\n$ chown postgres:postgres ${PGDATA?}/postgresql.conf\n$ chmod 0600 ${PGDATA?}/postgresql.conf\n\nTo remove superuser from a role, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER ROLE rolename WITH NOSUPERUSER\""
end
control "V-72857" do
  title "If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.\n\nAuthentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.\n\nIn such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.\n\nPostgreSQL passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000172-DB-000075"
  tag "gid": "V-72857"
  tag "rid": "SV-87509r1_rule"
  tag "stig_id": "PGS9-00-000800"
  tag "cci": "CCI-000197"
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), review the authentication entries in pg_hba.conf:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_hba.conf\n\nIf any entries use the auth_method (last column in records) \"password\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), edit pg_hba.conf authentication file and change all entries of \"password\" to \"md5\":\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/pg_hba.conf\nhost all all .example.com md5"
end
control "V-72859" do
  title "PostgreSQL must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies."
  desc  "Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access PostgreSQL. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies.\n\nSuccessful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.\n\nAccess control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.\n\nThis requirement is applicable to access control enforcement applications, a category that includes database management systems. If PostgreSQL does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-DB-000084"
  tag "gid": "V-72859"
  tag "rid": "SV-87511r1_rule"
  tag "stig_id": "PGS9-00-000900"
  tag "cci": "CCI-000213"
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "From the system security plan or equivalent documentation, determine the appropriate permissions on database objects for each kind (group role) of user. If this documentation is missing, this is a finding.\n\nFirst, as the database administrator (shown here as \"postgres\"), check the privileges of all roles in the database by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c '\\du'\n\nReview all roles and their associated privileges. If any roles' privileges exceed those documented, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), check the configured privileges for tables and columns by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c '\\dp'\n\nReview all access privileges and column access privileges list. If any roles' privileges exceed those documented, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), check the configured authentication settings in pg_hba.conf:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_hba.conf\n\nReview all entries and their associated authentication methods. If any entries do not have their documented authentication requirements, this is a finding."
  tag "fix": "Create and/or maintain documentation of each group role's appropriate permissions on database objects.\n\nImplement these permissions in the database, and remove any permissions that exceed those documented.\n\n- - - - -\n\nThe following are examples of how to use role privileges in PostgreSQL to enforce access controls. For a complete list of privileges, see the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html\n\n#### Roles Example 1\n\nThe following example demonstrates how to create an admin role with CREATEDB and CREATEROLE privileges.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE admin WITH CREATEDB CREATEROLE\"\n\n#### Roles Example 2\n\nThe following example demonstrates how to create a role with a password that expires and makes the role a member of the \"admin\" group.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE joe LOGIN ENCRYPTED PASSWORD 'stig2016!' VALID UNTIL '2016-09-20' IN ROLE admin\"\n\n#### Roles Example 3\n\nThe following demonstrates how to revoke privileges from a role using REVOKE.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"REVOKE admin FROM joe\"\n\n#### Roles Example 4\n\nThe following demonstrates how to alter privileges in a role using ALTER.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER ROLE joe NOLOGIN\"\n\nThe following are examples of how to use grant privileges in PostgreSQL to enforce access controls on objects. For a complete list of privileges, see the official documentation: https://www.postgresql.org/docs/current/static/sql-grant.html\n\n#### Grant Example 1\n\nThe following example demonstrates how to grant INSERT on a table to a role.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"GRANT SELECT ON stig_test TO joe\"\n\n#### Grant Example 2\n\nThe following example demonstrates how to grant ALL PRIVILEGES on a table to a role.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"GRANT ALL PRIVILEGES ON stig_test TO joe\"\n\n#### Grant Example 3\n\nThe following example demonstrates how to grant a role to a role.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"GRANT admin TO joe\"\n\n#### Revoke Example 1\n\nThe following example demonstrates how to revoke access from a role.\n\nAs the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"REVOKE admin FROM joe\"\n\nTo change authentication requirements for the database, as the database administrator (shown here as \"postgres\"), edit pg_hba.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/pg_hba.conf\n\nEdit authentication requirements to the organizational requirements. See the official documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html\n\nAfter changes to pg_hba.conf, reload the server:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72861" do
  title "PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in transmission."
  desc  "Without the association of security labels to information, there is no basis for PostgreSQL to make security-related access-control decisions.\n\nSecurity labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. \n\nThese labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. \n\nOne example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000314-DB-000310"
  tag "gid": "V-72861"
  tag "rid": "SV-87513r1_rule"
  tag "stig_id": "PGS9-00-001100"
  tag "cci": "CCI-002264"
  tag "nist": ["AC-16 a", "Rev_4"]
  tag "check": "If security labeling is not required, this is not a finding.\n\nFirst, as the database administrator (shown here as \"postgres\"), run the following SQL against each table that requires security labels:\n\n$ sudo su - postgres\n$ psql -c \"\\d+ <schema_name>.<table_name>\"\n\nIf security labeling is required and the results of the SQL above do not show a policy attached to the table, this is a finding.\n\nIf security labeling is required and not implemented according to the system documentation, such as SSP, this is a finding.\n\nIf security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in storage, this is a finding."
  tag "fix": "In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).\n\nRLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, see supplementary content APPENDIX-D."
end
control "V-72863" do
  title "PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types."
  desc  "Database management includes the ability to control the number of users and user sessions utilizing PostgreSQL. Unlimited concurrent connections to PostgreSQL could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.\n\nThis requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.\n\nThe capability to limit the number of concurrent sessions per user must be configured in or added to PostgreSQL (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to PostgreSQL by other means.\n\nThe organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.\n\n(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-DB-000031"
  tag "gid": "V-72863"
  tag "rid": "SV-87515r1_rule"
  tag "stig_id": "PGS9-00-001200"
  tag "cci": "CCI-000054"
  tag "nist": ["AC-10", "Rev_4"]
  tag "check": "To check the total amount of connections allowed by the database, as the database administrator, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW max_connections\"\n\nIf the total amount of connections is greater than documented by an organization, this is a finding.\n\nTo check the amount of connections allowed for each role, as the database administrator, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SELECT rolname, rolconnlimit from pg_authid\"\n\nIf any roles have more connections configured than documented, this is a finding. A value of -1 indicates Unlimited, and is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo configure the maximum amount of connections allowed to the database, as the database administrator (shown here as \"postgres\") change the following in postgresql.conf (the value 10 is an example; set the value to suit local conditions):\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nmax_connections = 10\n\nNext, restart the database:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl restart postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 restart\n\nTo limit the amount of connections allowed by a specific role, as the database administrator, run the following SQL:\n\n$ psql -c \"ALTER ROLE <rolname> CONNECTION LIMIT 1\";"
end
control "V-72865" do
  title "The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (functions, trigger procedures, links to software external to PostgreSQL, etc.) must be restricted to authorized users."
  desc  "If PostgreSQL were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.\n\nAccordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.\n\nUnmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000362"
  tag "gid": "V-72865"
  tag "rid": "SV-87517r1_rule"
  tag "stig_id": "PGS9-00-001300"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), list all users and their permissions by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\dp *.*\"\n\nVerify that all objects have the correct privileges. If they do not, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), verify the permissions of the database directory on the filesystem:\n\n$ ls -la ${PGDATA?}\n\nIf permissions of the database directory are not limited to an authorized user account, this is a finding."
  tag "fix": "As the database administrator, revoke any permissions from a role that are deemed unnecessary by running the following SQL:\n\nALTER ROLE bob NOCREATEDB;\nALTER ROLE bob NOCREATEROLE;\nALTER ROLE bob NOSUPERUSER;\nALTER ROLE bob NOINHERIT;\nREVOKE SELECT ON some_function FROM bob;"
end
control "V-72867" do
  title "PostgreSQL must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users)."
  desc  "Non-organizational users include all information system users other than organizational users, which includes organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). \n\nNon-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. \n\nAccordingly, a risk assessment is used in determining the authentication needs of the organization. \n\nScalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000180-DB-000115"
  tag "gid": "V-72867"
  tag "rid": "SV-87519r1_rule"
  tag "stig_id": "PGS9-00-001400"
  tag "cci": "CCI-000804"
  tag "nist": ["IA-8", "Rev_4"]
  tag "check": "PostgreSQL uniquely identifies and authenticates PostgreSQL users through the use of DBMS roles. \n\nTo list all roles in the database, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\du\"\n\nIf users are not uniquely identified as per organizational documentation, this is a finding."
  tag "fix": "To drop a role, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"DROP ROLE <role_to_drop>\"\n\nTo create a role, as the database administrator, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE <role name> LOGIN\"\n\nFor the complete list of permissions allowed by roles, see the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html"
end
control "V-72869" do
  title "PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in storage."
  desc  "Without the association of security labels to information, there is no basis for PostgreSQL to make security-related access-control decisions.\n\nSecurity labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. \n\nThese labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. \n\nOne example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000311-DB-000308"
  tag "gid": "V-72869"
  tag "rid": "SV-87521r1_rule"
  tag "stig_id": "PGS9-00-001700"
  tag "cci": "CCI-002262"
  tag "nist": ["AC-16 a", "Rev_4"]
  tag "check": "If security labeling is not required, this is not a finding.\n\nFirst, as the database administrator (shown here as \"postgres\"), run the following SQL against each table that requires security labels:\n\n$ sudo su - postgres\n$ psql -c \"\\d+ <schema_name>.<table_name>\"\n\nIf security labeling is required and the results of the SQL above do not show a policy attached to the table, this is a finding.\n\nIf security labeling is required and not implemented according to the system documentation, such as SSP, this is a finding.\n\nIf security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in storage, this is a finding."
  tag "fix": "In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).\n\nRLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, see supplementary content APPENDIX-D."
end
control "V-72871" do
  title "PostgreSQL must check the validity of all data inputs except those specifically identified by the organization."
  desc  "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.\n\nWith respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.\n\nEven when no such hijacking takes place, invalid input that gets recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate.\n\nThis calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000160"
  tag "gid": "V-72871"
  tag "rid": "SV-87523r1_rule"
  tag "stig_id": "PGS9-00-001800"
  tag "cci": "CCI-001310"
  tag "nist": ["SI-10", "Rev_4"]
  tag "check": "Review PostgreSQL code (trigger procedures, functions), application code, settings, column and field definitions, and constraints to determine whether the database is protected against invalid input.\n\nIf code exists that allows invalid data to be acted upon or input into the database, this is a finding.\n\nIf column/field definitions do not exist in the database, this is a finding.\n\nIf columns/fields do not contain constraints and validity checking where required, this is a finding.\n\nWhere a column/field is noted in the system documentation as necessarily free-form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding.\n\nWhere a column/field is clearly identified by name, caption or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.\n\nCheck application code that interacts with PostgreSQL for the use of prepared statements. If prepared statements are not used, this is a finding."
  tag "fix": "Modify database code to properly validate data before it is put into the database or acted upon by the database.\n\nModify the database to contain constraints and validity checking on database columns and tables that require them for data integrity.\n\nUse prepared statements when taking user input. \n\nDo not allow general users direct console access to PostgreSQL."
end
control "V-72873" do
  title "PostgreSQL and associated applications must reserve the use of dynamic code execution for situations that require it."
  desc  "With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.\n\nThe principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).\n\nThis calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000391"
  tag "gid": "V-72873"
  tag "rid": "SV-87525r1_rule"
  tag "stig_id": "PGS9-00-001900"
  tag "cci": "CCI-001310"
  tag "nist": ["SI-10", "Rev_4"]
  tag "check": "Review PostgreSQL source code (trigger procedures, functions) and application source code, to identify cases of dynamic code execution. Any user input should be handled through prepared statements. \n\nIf dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, this is a finding."
  tag "fix": "Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so."
end
control "V-72875" do
  title "PostgreSQL and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack."
  desc  "With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.\n\nThe principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).\n\nWhen dynamic execution is necessary, ways to mitigate the risk include the following, which should be implemented both in the on-screen application and at the database level, in the stored procedures:\n-- Allow strings as input only when necessary. \n-- Rely on data typing to validate numbers, dates, etc. Do not accept invalid values. If substituting other values for them, think carefully about whether this could be subverted.\n-- Limit the size of input strings to what is truly necessary.\n-- If single quotes/apostrophes, double quotes, semicolons, equals signs, angle brackets, or square brackets will never be valid as input, reject them.\n-- If comment markers will never be valid as input, reject them. In SQL, these are -- or /* */ \n-- If HTML and XML tags, entities, comments, etc., will never be valid, reject them.\n-- If wildcards are present, reject them unless truly necessary. In SQL these are the underscore and the percentage sign, and the word ESCAPE is also a clue that wildcards are in use.\n-- If SQL key words, such as SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ESCAPE, UNION, GRANT, REVOKE, DENY, MODIFY will never be valid, reject them. Use case-insensitive comparisons when searching for these. Bear in mind that some of these words, particularly Grant (as a person's name), could also be valid input. \n-- If there are range limits on the values that may be entered, enforce those limits.\n-- Institute procedures for inspection of programs for correct use of dynamic coding, by a party other than the developer.\n-- Conduct rigorous testing of program modules that use dynamic coding, searching for ways to subvert the intended use.\n-- Record the inspection and testing in the system documentation.\n-- Bear in mind that all this applies not only to screen input, but also to the values in an incoming message to a web service or to a stored procedure called by a software component that has not itself been hardened in these ways. Not only can the caller be subject to such vulnerabilities; it may itself be the attacker."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000392"
  tag "gid": "V-72875"
  tag "rid": "SV-87527r1_rule"
  tag "stig_id": "PGS9-00-002000"
  tag "cci": "CCI-001310"
  tag "nist": ["SI-10", "Rev_4"]
  tag "check": "Review PostgreSQL source code (trigger procedures, functions) and application source code to identify cases of dynamic code execution.\n\nIf dynamic code execution is employed without protective measures against code injection, this is a finding."
  tag "fix": "Where dynamic code execution is used, modify the code to implement protections against code injection (IE: prepared statements)."
end
control "V-72877" do
  title "PostgreSQL must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements."
  desc  "In order to ensure sufficient storage capacity for the audit logs, PostgreSQL must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.\n\nThe task of allocating audit record storage capacity is usually performed during initial installation of PostgreSQL and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.\n\nIn determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on PostgreSQL's ability to reuse the space formerly occupied by off-loaded records."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000357-DB-000316"
  tag "gid": "V-72877"
  tag "rid": "SV-87529r1_rule"
  tag "stig_id": "PGS9-00-002100"
  tag "cci": "CCI-001849"
  tag "nist": ["AU-4", "Rev_4"]
  tag "check": "Investigate whether there have been any incidents where PostgreSQL ran out of audit log space since the last time the space was allocated or other corrective measures were taken.\n\nIf there have been incidents where PostgreSQL ran out of audit log space, this is a finding."
  tag "fix": "Allocate sufficient audit file/table space to support peak demand."
end
control "V-72883" do
  title "PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects."
  desc  "Discretionary Access Control (DAC) is based on the notion that individual users are \"owners\" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.\n\nWhen discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. \n\nA subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. \n\nThe policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-72883"
  tag "rid": "SV-87535r1_rule"
  tag "stig_id": "PGS9-00-002200"
  tag "cci": "CCI-002165"
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "check": "Review system documentation to identify the required discretionary access control (DAC).\n\nReview the security configuration of the database and PostgreSQL. If applicable, review the security configuration of the application(s) using the database.\n\nIf the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.\n\nIf any database objects are found to be owned by users not authorized to own database objects, this is a finding.\n\nTo check the ownership of objects in the database, as the database administrator, run the following:\n\n$ sudo su - postgres\n$ psql -c \"\\dn *.*\"\n$ psql -c \"\\dt *.*\"\n$ psql -c \"\\ds *.*\"\n$ psql -c \"\\dv *.*\"\n$ psql -c \"\\df+ *.*\"\n\nIf any role is given privileges to objects it should not have, this is a finding."
  tag "fix": "Implement the organization's DAC policy in the security configuration of the database and PostgreSQL, and, if applicable, the security configuration of the application(s) using the database.\n\nTo GRANT privileges to roles, as the database administrator (shown here as \"postgres\"), run statements like the following examples:\n\n$ sudo su - postgres\n$ psql -c \"CREATE SCHEMA test\"\n$ psql -c \"GRANT CREATE ON SCHEMA test TO bob\"\n$ psql -c \"CREATE TABLE test.test_table(id INT)\"\n$ psql -c \"GRANT SELECT ON TABLE test.test_table TO bob\"\n\nTo REVOKE privileges to roles, as the database administrator (shown here as \"postgres\"), run statements like the following examples:\n\n$ psql -c \"REVOKE SELECT ON TABLE test.test_table FROM bob\"\n$ psql -c \"REVOKE CREATE ON SCHEMA test FROM bob\""
end
control "V-72885" do
  title "The audit information produced by PostgreSQL must be protected from unauthorized deletion."
  desc  "If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.\n\nTo ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.\n\nSome commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.\n\nApplications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.\n\nAudit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.\n\nDeletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000120-DB-000061"
  tag "gid": "V-72885"
  tag "rid": "SV-87537r1_rule"
  tag "stig_id": "PGS9-00-002300"
  tag "cci": "CCI-000164"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nReview locations of audit logs, both internal to the database and database audit logs located at the operating system level.\n\nVerify there are appropriate controls and permissions to protect the audit information from unauthorized modification.\n\n#### stderr Logging\n\nIf the PostgreSQL server is configured to use stderr for logging, the logs will be owned by the database administrator (shown here as \"postgres\") with a default permissions level of 0600. The permissions can be configured in postgresql.conf.\n\nTo check the permissions for log files in postgresql.conf, as the database administrator (shown here as \"postgres\"), run the following command:\n\n$ sudo su - postgres\n$ grep \"log_file_mode\" ${PGDATA?}/postgresql.conf\n\nIf the permissions are not 0600, this is a finding.\n\nNext, navigate to where the logs are stored. This can be found by running the following command against postgresql.conf as the database administrator (shown here as \"postgres\"):\n\n$ sudo su - postgres\n$ grep \"log_directory\" ${PGDATA?}/postgresql.conf\n\nWith the log directory identified, as the database administrator (shown here as \"postgres\"), list the permissions of the logs:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}/pg_log\n\nIf logs are not owned by the database administrator (shown here as \"postgres\") and are not the same permissions as configured in postgresql.conf, this is a finding.\n\n#### syslog Logging\n\nIf the PostgreSQL server is configured to use syslog for logging, consult the organizations syslog setting for permissions and ownership of logs."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nBy default, the database administrator account is not accessible by unauthorized users. Only grant access to this account if required for operations.\n\n#### stderr Logging\n\nBy default, the database administrator account is not accessible by unauthorized users. Only grant access to this account if required for operations.\n\nWith stderr logging enabled, as the database administrator (shown here as \"postgres\"), set the following parameter in postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_file_mode = 0600\n\n#### syslog Logging\n\nCheck with the organization to see how syslog facilities are defined in their organization."
end
control "V-72887" do
  title "PostgreSQL must record time stamps, in audit records and application data, that can be mapped to Coordinated Universal Time (UTC, formerly GMT)."
  desc  "If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis.\n\nTime stamps generated by PostgreSQL must include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000374-DB-000322"
  tag "gid": "V-72887"
  tag "rid": "SV-87539r1_rule"
  tag "stig_id": "PGS9-00-002400"
  tag "cci": "CCI-001890"
  tag "nist": ["AU-8 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nWhen a PostgreSQL cluster is initialized using initdb, the PostgreSQL cluster will be configured to use the same time zone as the target server. \n\nAs the database administrator (shown here as \"postgres\"), check the current log_timezone setting by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_timezone\"\n\nlog_timezone\n--------------\nUTC\n(1 row)\n\nIf log_timezone is not set to the desired time zone, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo change log_timezone in postgresql.conf to use a different time zone for logs, as the database administrator (shown here as \"postgres\"), run the following:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_timezone='UTC'\n\nNext, restart the database:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl restart postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 restart"
end
control "V-72889" do
  title "PostgreSQL must reveal detailed error messages only to the ISSO, ISSM, SA and DBA."
  desc  "If PostgreSQL provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. \n\nSome default PostgreSQL error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. \n\nIt is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, \"An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk\" would be relevant. A message such as \"Warning: your transaction generated a large number of page splits\" would likely not be relevant. \n\nAdministrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000267-DB-000163"
  tag "gid": "V-72889"
  tag "rid": "SV-87541r1_rule"
  tag "stig_id": "PGS9-00-002500"
  tag "cci": "CCI-001314"
  tag "nist": ["SI-11 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nCheck PostgreSQL settings and custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.\n\nTo check the level of detail for errors exposed to clients, as the database administrator (shown here as \"postgres\"), run the following:\n\n$ sudo su - postgres\n$ grep \"client_min_messages\"\n${PGDATA?}/postgresql.conf\n\nIf client_min_messages is set to LOG or DEBUG, this is a finding.\n\nIf detailed error messages are displayed to individuals not authorized to view them, this is a finding.\n\n#### stderr Logging\n\nLogs may contain detailed information and should only be accessible by the database owner.\n\nAs the database administrator, verify the following settings of logs in the postgresql.conf file.\n\nNote: Consult the organization's documentation on acceptable log privileges\n\n$ sudo su - postgres\n$ grep log_directory ${PGDATA?}/postgresql.conf\n$ grep log_file_mode ${PGDATA?}/postgresql.conf\n\nNext, verify the log files have the set configurations.\n\nNote: Use location of logs from log_directory.\n\n$ ls -l <audit_log_path>\ntotal 32\n-rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log\n-rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log\n-rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log\n-rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log\n-rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log\n-rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log\n\nIf logs are not owned by the database administrator or have permissions that are not 0600, this is a finding.\n\n#### syslog Logging\n\nIf PostgreSQL is configured to use syslog for logging, consult the organizations location and permissions for syslog log files. If the logs are not owned by root or have permissions that are not 0600, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo set the level of detail for errors messages exposed to clients, as the database administrator (shown here as \"postgres\"), run the following commands:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nclient_min_messages = notice"
end
control "V-72891" do
  title "PostgreSQL must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited."
  desc  "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.\n\nSuppression of auditing could permit an adversary to evade detection.\n\nMisconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000090-DB-000065"
  tag "gid": "V-72891"
  tag "rid": "SV-87543r1_rule"
  tag "stig_id": "PGS9-00-002600"
  tag "cci": "CCI-000171"
  tag "nist": ["AU-12 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nCheck PostgreSQL settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.\n\nAs the database administrator (shown here as \"postgres\"), verify the permissions for PGDATA:\n\n$ ls -la ${PGDATA?}\n\nIf anything in PGDATA is not owned by the database administrator, this is a finding.\n\nNext, as the database administrator, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\du\"\n\nReview the role permissions, if any role is listed as superuser but should not have that access, this is a finding."
  tag "fix": "Configure PostgreSQL's settings to allow designated personnel to select which auditable events are audited.\n\nUsing pgaudit allows administrators the flexibility to choose what they log. For an overview of the capabilities of pgaudit, see https://github.com/pgaudit/pgaudit. \n\nSee supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nSee supplementary content APPENDIX-C for instructions on enabling logging. Only administrators/superuser can change PostgreSQL configurations. Access to the database administrator must be limited to designated personnel only.\n\nTo ensure that postgresql.conf is owned by the database owner:\n\n$ chown postgres:postgres ${PGDATA?}/postgresql.conf\n$ chmod 600 ${PGDATA?}/postgresql.conf"
end
control "V-72893" do
  title "PostgreSQL must provide an immediate real-time alert to appropriate support staff of all audit failure events requiring real-time alerts."
  desc  "It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. \n\nThe appropriate support staff include, at a minimum, the ISSO and the DBA/SA.\n\nAlerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).\n\nThe necessary monitoring and alerts may be implemented using features of PostgreSQL, the OS, third-party software, custom code, or a combination of these. The term \"the system\" is used to encompass all of these."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000360-DB-000320"
  tag "gid": "V-72893"
  tag "rid": "SV-87545r1_rule"
  tag "stig_id": "PGS9-00-002700"
  tag "cci": "CCI-001858"
  tag "nist": ["AU-5 (2)", "Rev_4"]
  tag "check": "Review the system documentation to determine which audit failure events require real-time alerts.\n\nReview the system settings and code. If the real-time alerting that is specified in the documentation is not enabled, this is a finding."
  tag "fix": "Configure the system to provide an immediate real-time alert to appropriate support staff when a specified audit failure occurs.\n\nIt is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in PostgreSQL."
end
control "V-72895" do
  title "PostgreSQL must maintain the confidentiality and integrity of information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.\n\nThis requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. \n\nWhen receiving data, PostgreSQL, associated applications, and infrastructure must leverage protection mechanisms.\n\nPostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c; while the name is misleading, this function enables only TLS encryption methods, not SSL.\n\nSee OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.htm."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000442-DB-000379"
  tag "gid": "V-72895"
  tag "rid": "SV-87547r1_rule"
  tag "stig_id": "PGS9-00-003000"
  tag "cci": "CCI-002422"
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "check": "If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.\n\nAs the database administrator (shown here as \"postgres\"), verify SSL is enabled in postgresql.conf by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl\" \n\nIf SSL is off, this is a finding.\n\nIf PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding."
  tag "fix": "Implement protective measures against unauthorized disclosure and modification during reception.\n\nTo configure PostgreSQL to use SSL, see supplementary content APPENDIX-G for instructions on enabling SSL."
end
control "V-72897" do
  title "Database objects (including but not limited to tables, indexes, storage, trigger procedures, functions, links to software external to PostgreSQL, etc.) must be owned by database/DBMS principals authorized for ownership."
  desc  "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.\n\nConversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000200"
  tag "gid": "V-72897"
  tag "rid": "SV-87549r1_rule"
  tag "stig_id": "PGS9-00-003100"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).\n\nIf any database objects are found to be owned by users not authorized to own database objects, this is a finding.\n\nTo check the ownership of objects in the database, as the database administrator, run the following SQL:\n\n$ sudo su - postgres\n$ psql -x -c \"\\dn *.*\"\n$ psql -x -c \"\\dt *.*\"\n$ psql -x -c \"\\ds *.*\"\n$ psql -x -c \"\\dv *.*\"\n$ psql -x -c \"\\df+ *.*\"\n\nIf any object is not owned by an authorized role for ownership, this is a finding."
  tag "fix": "Assign ownership of authorized objects to authorized object owner accounts.\n\n#### Schema Owner\n\nTo create a schema owned by the user bob, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE SCHEMA test AUTHORIZATION bob\n\nTo alter the ownership of an existing object to be owned by the user bob, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER SCHEMA test OWNER TO bob\""
end
control "V-72899" do
  title "The PostgreSQL software installation account must be restricted to authorized users."
  desc  "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. \n\nIf the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.\n\nAccordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.\n\nDBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000198"
  tag "gid": "V-72899"
  tag "rid": "SV-87551r1_rule"
  tag "stig_id": "PGS9-00-003200"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Review procedures for controlling, granting access to, and tracking use of the PostgreSQL software installation account(s).\n\nIf access or use of this account is not restricted to the minimum number of personnel required or if unauthorized access to the account has been granted, this is a finding."
  tag "fix": "Develop, document, and implement procedures to restrict and track use of the PostgreSQL software installation account."
end
control "V-72901" do
  title "Database software, including PostgreSQL configuration files, must be stored in dedicated directories separate from the host OS and other applications."
  desc  "When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.\n\nMultiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000199"
  tag "gid": "V-72901"
  tag "rid": "SV-87553r1_rule"
  tag "stig_id": "PGS9-00-003300"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "check": "Review the PostgreSQL software library directory and any subdirectories.\n\nIf any non-PostgreSQL software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use the PostgreSQL, this is a finding.\n\nOnly applications that are required for the functioning and administration, not use, of the PostgreSQL should be located in the same disk directory as the PostgreSQL software libraries.\n\nIf other applications are located in the same directory as PostgreSQL, this is a finding."
  tag "fix": "Install all applications on directories separate from the PostgreSQL software library directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL software library directory."
end
control "V-72903" do
  title "PostgreSQL must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.\n\nThe organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of users of shared accounts, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. \n\nExamples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of shared account users."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000101-DB-000044"
  tag "gid": "V-72903"
  tag "rid": "SV-87555r1_rule"
  tag "stig_id": "PGS9-00-003500"
  tag "cci": "CCI-000135"
  tag "nist": ["AU-3 (1)", "Rev_4"]
  tag "check": "Review the system documentation to identify what additional information the organization has determined necessary.\n\nCheck PostgreSQL settings and existing audit records to verify that all organization-defined additional, more detailed information is in the audit records for audit events identified by type, location, or subject.\n\nIf any additional information is defined and is not contained in the audit records, this is a finding."
  tag "fix": "Configure PostgreSQL audit settings to include all organization-defined detailed information in the audit records for audit events identified by type, location, or subject.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72905" do
  title "Execution of software modules (to include functions and trigger procedures) with elevated privileges must be restricted to necessary cases only."
  desc  "In certain situations, to provide required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.\n\nPrivilege elevation must be utilized only where necessary and protected from misuse.\n\nThis calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000342-DB-000302"
  tag "gid": "V-72905"
  tag "rid": "SV-87557r1_rule"
  tag "stig_id": "PGS9-00-003600"
  tag "cci": "CCI-002233"
  tag "nist": ["AC-6 (8)", "Rev_4"]
  tag "check": "Functions in PostgreSQL can be created with the SECURITY DEFINER option. When SECURITY DEFINER functions are executed by a user, said function is run with the privileges of the user who created it.\n\nTo list all functions that have SECURITY DEFINER, as, the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;\"\n\nIn the query results, a prosecdef value of \"t\" on a row indicates that that function uses privilege elevation.\n\nIf elevation of PostgreSQL privileges is utilized but not documented, this is a finding.\n\nIf elevation of PostgreSQL privileges is documented, but not implemented as described in the documentation, this is a finding.\n\nIf the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding."
  tag "fix": "Determine where, when, how, and by what principals/subjects elevated privilege is needed. \n\nTo change a SECURITY DEFINER function to SECURITY INVOKER, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER FUNCTION <function_name> SECURITY INVOKER;\""
end
control "V-72907" do
  title "When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives."
  desc  "A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.\n\nThe behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000447-DB-000393"
  tag "gid": "V-72907"
  tag "rid": "SV-87559r1_rule"
  tag "stig_id": "PGS9-00-003700"
  tag "cci": "CCI-002754"
  tag "nist": ["SI-10 (3)", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), make a small SQL syntax error in psql by running the following:\n\n$ sudo su - postgres\n$ psql -c \"CREAT TABLEincorrect_syntax(id INT)\"\nERROR: syntax error at or near \"CREAT\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the syntax error was logged (change the log file name and part to suit the circumstances):\n\n$ sudo su - postgres\n$ cat ~/9.5/data/pg_log/postgresql-Wed.log\n2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dERROR: syntax error at or near \"CRT\" at character 1\n2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dSTATEMENT: CRT TABLE incorrect_syntax(id INT);\n\nReview system documentation to determine how input errors from application to PostgreSQL are to be handled in general and if any special handling is defined for specific circumstances.\n\nIf it does not implement the documented behavior, this is a finding."
  tag "fix": "Enable logging.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nAll errors and denials are logged if logging is enabled."
end
control "V-72909" do
  title "PostgreSQL must utilize centralized management of the content captured in audit records generated by all components of PostgreSQL."
  desc  "Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.\n\nThe content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. \n\nPostgreSQL may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000356-DB-000314"
  tag "gid": "V-72909"
  tag "rid": "SV-87561r1_rule"
  tag "stig_id": "PGS9-00-003800"
  tag "cci": "CCI-001844"
  tag "nist": ["AU-3 (2)", "Rev_4"]
  tag "check": "On UNIX systems, PostgreSQL can be configured to use stderr, csvlog and syslog. To send logs to a centralized location, syslog should be used.\n\nAs the database owner (shown here as \"postgres\"), ensure PostgreSQL uses syslog by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_destination\"\n\nAs the database owner (shown here as \"postgres\"), check which log facility PostgreSQL is configured by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW syslog_facility\"\n\nCheck with the organization to see how syslog facilities are defined in their organization.\n\nIf PostgreSQL audit records are not written directly to or systematically transferred to a centralized log management system, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nWith logging enabled, as the database owner (shown here as \"postgres\"), configure the follow parameters in postgresql.conf:\n\nNote: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.\n\n$ sudo su - postgres\n$ vi 'log_destination' ${PGDATA?}/postgresql.conf\nlog_destination = 'syslog'\nsyslog_facility = 'LOCAL0'\nsyslog_ident = 'postgres'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72911" do
  title "PostgreSQL must isolate security functions from non-security functions."
  desc  "An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.\n\nSecurity functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.\n\nDevelopers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.\n\nDatabase Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000233-DB-000124"
  tag "gid": "V-72911"
  tag "rid": "SV-87563r1_rule"
  tag "stig_id": "PGS9-00-004000"
  tag "cci": "CCI-001084"
  tag "nist": ["SC-3", "Rev_4"]
  tag "check": "Check PostgreSQL settings to determine whether objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.\n\nBy default, all objects in pg_catalog and information_schema are owned by the database administrator. \n\nTo check the access controls for those schemas, as the database administrator (shown here as \"postgres\"), run the following commands to review the access privileges granted on the data dictionary and security tables, views, sequences, functions and trigger procedures:\n\n$ sudo su - postgres\n$ psql -x -c \"\\dp pg_catalog.*\"\n$ psql -x -c \"\\dp information_schema.*\"\n\nRepeat the \\dp statements for any additional schemas that contain locally defined security objects.\n\nRepeat using \\df+*.* to review ownership of PostgreSQL functions:\n\n$ sudo su - postgres\n$ psql -x -c \"\\df+ pg_catalog.*\"\n$ psql -x -c \"\\df+ information_schema.*\"\n\nRefer to the PostgreSQL online documentation for GRANT for help in interpreting the Access Privileges column in the output from \\du. Note that an entry starting with an equals sign indicates privileges granted to Public (all users). By default, most of the tables and views in the pg_catalog and information_schema schemas can be read by Public.\n\nIf any user besides the database administrator(s) is listed in access privileges and not documented, this is a finding.\n\nIf security-related database objects or code are not kept separate, this is a finding."
  tag "fix": "Do not locate security-related database objects with application tables or schema.\n\nReview any site-specific applications security modules built into the database: determine what schema they are located in and take appropriate action.\n\nDo not grant access to pg_catalog or information_schema to anyone but the database administrator(s). Access to the database administrator account(s) must not be granted to anyone without official approval."
end
control "V-72913" do
  title "PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes to the configuration of PostgreSQL or database(s)."
  desc  "Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions.\n\nEnforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000381-DB-000361"
  tag "gid": "V-72913"
  tag "rid": "SV-87565r1_rule"
  tag "stig_id": "PGS9-00-004100"
  tag "cci": "CCI-001814"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo verify that system denies are logged when unprivileged users attempt to change database configuration, as the database administrator (shown here as \"postgres\"), run the following commands:\n\n$ sudo su - postgres\n$ psql\n\nNext, create a role with no privileges, change the current role to that user and attempt to change a configuration by running the following SQL:\n\nCREATE ROLE bob;\nSET ROLE bob;\nSET pgaudit.role='test';\n\nNow check pg_log (use the latest log):\n\n$ cat ${PGDATA?}/pg_log/postgresql-Thu.log\n< 2016-01-28 17:57:34.092 UTC bob postgres: >ERROR: permission denied to set parameter \"pgaudit.role\"\n< 2016-01-28 17:57:34.092 UTC bob postgres: >STATEMENT: SET pgaudit.role='test';\n\nIf the denial is not logged, this is a finding.\n\nBy default PostgreSQL configuration files are owned by the postgres user and cannot be edited by non-privileged users:\n\n$ ls -la ${PGDATA?} | grep postgresql.conf\n-rw-------. 1 postgres postgres 21758 Jan 22 10:27 postgresql.conf\n\nIf postgresql.conf is not owned by the database owner and does not have read and write permissions for the owner, this is a finding."
  tag "fix": "Enable logging.\n\nAll denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72915" do
  title "The audit information produced by PostgreSQL must be protected from unauthorized read access."
  desc  "If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.\n\nTo ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.\n\nThis requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location.\n\nAdditionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.\n\nAudit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000118-DB-000059"
  tag "gid": "V-72915"
  tag "rid": "SV-87567r1_rule"
  tag "stig_id": "PGS9-00-004200"
  tag "cci": "CCI-000162"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nReview locations of audit logs, both internal to the database and database audit logs located at the operating system level.\n\nVerify there are appropriate controls and permissions to protect the audit information from unauthorized access.\n\n#### syslog Logging\n\nIf PostgreSQL is configured to use syslog for logging, consult the organizations location and permissions for syslog log files.\n\n#### stderr Logging\n\nAs the database administrator (shown here as \"postgres\"), check the current log_file_mode configuration by running the following:\n\nNote: Consult the organization's documentation on acceptable log privileges\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_file_mode\"\n\nIf log_file_mode is not 600, this is a finding.\n\nNext, check the current log_destination path by running the following SQL:\n\nNote: This is relative to PGDATA.\n\n$ psql -c \"SHOW log_destination\"\n\nNext, verify the log files have the set configurations in the log_destination:\n\nNote: Use location of logs from log_directory.\n\n$ ls -l ${PGDATA?}/pg_log/\ntotal 32\n-rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log\n-rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log\n-rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log\n-rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log\n-rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log\n-rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log\n\nIf logs with 600 permissions do not exist in log_destination, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\n#### syslog Logging\n\nIf PostgreSQL is configured to use syslog for logging, consult the organizations location and permissions for syslog log files.\n\n#### stderr Logging\n\nIf PostgreSQL is configured to use stderr for logging, permissions of the log files can be set in postgresql.conf.\n\nAs the database administrator (shown here as \"postgres\"), edit the following settings of logs in the postgresql.conf file:\n\nNote: Consult the organization's documentation on acceptable log privileges\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_file_mode = 0600\n\nNext, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72917" do
  title "When updates are applied to PostgreSQL software, any software components that have been replaced or made unnecessary must be removed."
  desc  "Previous versions of PostgreSQL components that are not removed from the information system after updates have been installed may be exploited by adversaries.\n\nSome PostgreSQL installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.\n\nA transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-72917"
  tag "rid": "SV-87569r1_rule"
  tag "stig_id": "PGS9-00-004300"
  tag "cci": "CCI-002617"
  tag "nist": ["SI-2 (6)", "Rev_4"]
  tag "check": "To check software installed by packages, as the system administrator, run the following command:\n\n# RHEL/CENT Systems\n$ sudo rpm -qa | grep postgres\n\nIf multiple versions of postgres are installed but are unused, this is a finding."
  tag "fix": "Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated."
end
control "V-72919" do
  title "PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is accessed."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000494-DB-000344"
  tag "gid": "V-72919"
  tag "rid": "SV-87571r1_rule"
  tag "stig_id": "PGS9-00-004400"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW pgaudit.log\"\n\nIf pgaudit.log does not contain, \"ddl, write, role\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing `pgaudit` the DBMS (PostgreSQL) can be configured to audit these requests. See supplementary content `APPENDIX-B` for documentation on installing `pgaudit`.\n\nWith `pgaudit` installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'ddl, write, role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72921" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to access security objects occur."
  desc  "Changes to the security configuration must be tracked.\n\nThis requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.\n\nIn an SQL environment, types of access include, but are not necessarily limited to:\n\nSELECT\nINSERT\nUPDATE\nDELETE\nEXECUTE\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000492-DB-000333"
  tag "gid": "V-72921"
  tag "rid": "SV-87573r1_rule"
  tag "stig_id": "PGS9-00-004500"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), setup a test schema and revoke users privileges from using it by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE SCHEMA stig_test_schema AUTHORIZATION postgres\"\n$ psql -c \"REVOKE ALL ON SCHEMA stig_test_schema FROM public\"\n$ psql -c \"GRANT ALL ON SCHEMA stig_test_schema TO postgres\"\n\nNext, create a test table, insert a value into that table for the following checks by running the following SQL:\n\n$ psql -c \"CREATE TABLE stig_test_schema.stig_test_table(id INT)\"\n$ psql -c \"INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0)\"\n\n#### CREATE\nAttempt to CREATE a table in the stig_test_schema schema with a role that does not have privileges by running the following SQL:\n\npsql -c \"CREATE ROLE bob; SET ROLE bob; CREATE TABLE stig_test_schema.test_table(id INT);\"\nERROR: permission denied for schema stig_test_schema\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 09:55:19.423 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 14\n< 2016-03-09 09:55:19.423 EST postgres 56e0393f.186b postgres: >STATEMENT: CREATE TABLE stig_test_schema.test_table(id INT);\n\nIf the denial is not logged, this is a finding.\n\n#### INSERT\nAs role bob, attempt to INSERT into the table created earlier, stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0);\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 09:58:30.709 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 13\n< 2016-03-09 09:58:30.709 EST postgres 56e0393f.186b postgres: >STATEMENT: INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0);\n\nIf the denial is not logged, this is a finding.\n\n#### SELECT\nAs role bob, attempt to SELECT from the table created earlier, stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; SELECT * FROM stig_test_schema.stig_test_table;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 09:57:58.327 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 15\n< 2016-03-09 09:57:58.327 EST postgres 56e0393f.186b postgres: >STATEMENT: SELECT * FROM stig_test_schema.stig_test_table;\n\nIf the denial is not logged, this is a finding.\n\n#### ALTER\nAs role bob, attempt to ALTER the table created earlier, stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; ALTER TABLE stig_test_schema.stig_test_table ADD COLUMN name TEXT;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 10:03:43.765 EST postgres 56e0393f.186b postgres: >STATEMENT: ALTER TABLE stig_test_schema.stig_test_table ADD COLUMN name TEXT;\n\nIf the denial is not logged, this is a finding.\n\n#### UPDATE\nAs role bob, attempt to UPDATE a row created earlier, stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; UPDATE stig_test_schema.stig_test_table SET id=1 WHERE id=0;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 10:08:27.696 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 8\n< 2016-03-09 10:08:27.696 EST postgres 56e0393f.186b postgres: >STATEMENT: UPDATE stig_test_schema.stig_test_table SET id=1 WHERE id=0;\n\nIf the denial is not logged, this is a finding.\n\n#### DELETE\nAs role bob, attempt to DELETE a row created earlier, stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; DELETE FROM stig_test_schema.stig_test_table WHERE id=0;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 10:09:29.607 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema at character 13\n< 2016-03-09 10:09:29.607 EST postgres 56e0393f.186b postgres: >STATEMENT: DELETE FROM stig_test_schema.stig_test_table WHERE id=0;\n\nIf the denial is not logged, this is a finding.\n\n#### PREPARE \nAs role bob, attempt to execute a prepared system using PREPARE by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; PREPARE stig_test_plan(int) AS SELECT id FROM stig_test_schema.stig_test_table WHERE id=$1;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 10:16:22.628 EST postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema stig_test_schema at character 46\n< 2016-03-09 10:16:22.628 EST postgres 56e03e02.18e4 postgres: >STATEMENT: PREPARE stig_test_plan(int) AS SELECT id FROM stig_test_schema.stig_test_table WHERE id=$1;\n\nIf the denial is not logged, this is a finding.\n\n#### DROP\nAs role bob, attempt to DROP the table created earlier stig_test_table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; DROP TABLE stig_test_schema.stig_test_table;\"\n\nNext, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-09 10:18:55.255 EST postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema stig_test_schema\n< 2016-03-09 10:18:55.255 EST postgres 56e03e02.18e4 postgres: >STATEMENT: DROP TABLE stig_test_schema.stig_test_table;\n\nIf the denial is not logged, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to access security objects occur.\n\nAll denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72923" do
  title "PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed attempts to log on to PostgreSQL. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000351"
  tag "gid": "V-72923"
  tag "rid": "SV-87575r1_rule"
  tag "stig_id": "PGS9-00-004600"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nIn this example the user joe will log into the Postgres database unsuccessfully:\n\n$ psql -d postgres -U joe\n\nAs the database administrator (shown here as \"postgres\"), check pg_log for a FATAL connection audit trail:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/postgresql-Tue.log\n< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >LOG: connection authorized: user=joe database=postgres\n< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >FATAL: role \"joe\" does not exist\n\nIf an audit record is not generated each time a user (or other principal) attempts, but fails to log on or connect to PostgreSQL (including attempts where the user ID is invalid/unknown), this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier.\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters:\n\nlog_connections = on\nlog_line_prefix = '< %m %u %c: >' \n\nWhere:\n* %m is the time and date\n* %u is the username\n* %c is the session ID for the connection\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72925" do
  title "PostgreSQL must generate audit records showing starting and ending time for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to PostgreSQL lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.\n\nDisconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000505-DB-000352"
  tag "gid": "V-72925"
  tag "rid": "SV-87577r1_rule"
  tag "stig_id": "PGS9-00-004700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, log into the database with the postgres user by running the following commands:\n\n$ sudo su - postgres\n$ psql -U postgres\n\nNext, as the database administrator, verify the log for a connection audit trail:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/postgresql-Tue.log\n< 2016-02-23 20:25:39.931 EST postgres 56cfa993.7a72 postgres: >LOG: connection authorized: user=postgres database=postgres\n< 2016-02-23 20:27:45.428 EST postgres 56cfa993.7a72 postgres: >LOG: AUDIT: SESSION,1,1,READ,SELECT,,,SELECT current_user;,<none>\n< 2016-02-23 20:27:47.988 EST postgres 56cfa993.7a72 postgres: >LOG: disconnection: session time: 0:00:08.057 user=postgres database=postgres host=[local]\n\nIf connections are not logged, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier.\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf by running the following:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters:\n\nlog_connections = on\nlog_disconnections = on\nlog_line_prefix = '< %m %u %c: >' \n\nWhere:\n* %m is the time and date\n* %u is the username\n* %c is the session ID for the connection\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72927" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur."
  desc  "Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000335"
  tag "gid": "V-72927"
  tag "rid": "SV-87579r1_rule"
  tag "stig_id": "PGS9-00-004800"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), create a test role by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob\"\n\nNext, to test if audit records are generated from unsuccessful attempts at modifying security objects, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';\"\n\nNext, as the database administrator (shown here as \"postgres\"), verify that the denials were logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission denied for relation pg_authid\n< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT: UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';\n\nIf denials are not logged, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security objects occur.\n\nUnsuccessful attempts to modifying security objects can be logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72929" do
  title "PostgreSQL must generate audit records when privileges/permissions are added."
  desc  "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.\n\nIn an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE command."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000326"
  tag "gid": "V-72929"
  tag "rid": "SV-87581r1_rule"
  tag "stig_id": "PGS9-00-004900"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), create a role by running the following SQL:\n\nChange the privileges of another user:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob\"\n\nNext, GRANT then REVOKE privileges from the role:\n\n$ psql -c \"GRANT CONNECT ON DATABASE postgres TO bob\"\n$ psql -c \"REVOKE CONNECT ON DATABASE postgres FROM bob\"\n\npostgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;\nREVOKE\n\npostgres=# GRANT CONNECT ON DATABASE postgres TO bob;\nGRANT\n\nNow, as the database administrator (shown here as \"postgres\"), verify the events were logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-07-13 16:25:21.103 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE postgres TO bob,<none>\n< 2016-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE postgres FROM bob,<none>\n\nIf the above steps cannot verify that audit records are produced when privileges/permissions/role memberships are added, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72931" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000502-DB-000349"
  tag "gid": "V-72931"
  tag "rid": "SV-87583r1_rule"
  tag "stig_id": "PGS9-00-005000"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain \"pgaudit\", this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAll errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72933" do
  title "PostgreSQL must generate audit records when successful logons or connections occur."
  desc  "For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to PostgreSQL."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000350"
  tag "gid": "V-72933"
  tag "rid": "SV-87585r1_rule"
  tag "stig_id": "PGS9-00-005100"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), check if log_connections is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_connections\"\n\nIf log_connections is off, this is a finding.\n\nNext, verify the logs that the previous connection to the database was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-02-16 15:54:03.934 EST postgres postgres 56c64b8b.aeb: >LOG: connection authorized: user=postgres database=postgres\n\nIf an audit record is not generated each time a user (or other principal) logs on or connects to PostgreSQL, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier.\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters as such:\n\nlog_connections = on\nlog_line_prefix = '< %m %u %d %c: >' \n\nWhere:\n* %m is the time and date\n* %u is the username\n* %d is the database\n* %c is the session ID for the connection\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72939" do
  title "PostgreSQL must generate audit records when security objects are deleted."
  desc  "The removal of security objects from the database/PostgreSQL would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000336"
  tag "gid": "V-72939"
  tag "rid": "SV-87591r1_rule"
  tag "stig_id": "PGS9-00-005200"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), create a test table stig_test, enable row level security, and create a policy by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE TABLE stig_test(id INT)\"\n$ psql -c \"ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY\"\n$ psql -c \"CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user)\"\n\nNext, drop the policy and disable row level security:\n\n$ psql -c \"DROP POLICY lock_table ON stig_test\"\n$ psql -c \"ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the security objects deletions were logged:\n\n$ cat ${PGDATA?}/pg_log/<latest_log>\n2016-03-30 14:54:18.991 EDT postgres postgres LOG: AUDIT: SESSION,11,1,DDL,DROP POLICY,,,DROP POLICY lock_table ON stig_test;,<none>\n2016-03-30 14:54:42.373 EDT postgres postgres LOG: AUDIT: SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY;,<none>\n\nIf audit records are not produced when security objects are dropped, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'ddl'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72941" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur."
  desc  "Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such information available through views or functions.\n\nThis requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000325"
  tag "gid": "V-72941"
  tag "rid": "SV-87593r1_rule"
  tag "stig_id": "PGS9-00-005300"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), create a role 'bob' by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob\"\n\nNext, attempt to retrieve information from the pg_authid table:\n\n$ psql -c \"SET ROLE bob; SELECT * FROM pg_authid\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the event was logged in pg_log:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-07-13 16:49:58.864 EDT postgres postgres ERROR: > permission denied for relation pg_authid\n< 2016-07-13 16:49:58.864 EDT postgres postgres STATEMENT: > SELECT * FROM pg_authid;\n\nIf the above steps cannot verify that audit records are produced when PostgreSQL denies retrieval of privileges/permissions/role memberships, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.\n\nAll denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72945" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.\n\nIn an SQL environment, deleting permissions is typically done via the REVOKE command.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000499-DB-000331"
  tag "gid": "V-72945"
  tag "rid": "SV-87597r1_rule"
  tag "stig_id": "PGS9-00-005400"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), create the roles joe and bob with LOGIN by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE joe LOGIN\"\n$ psql -c \"CREATE ROLE bob LOGIN\"\n\nNext, set current role to bob and attempt to alter the role joe:\n\n$ psql -c \"SET ROLE bob; ALTER ROLE joe NOLOGIN\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the denials are logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >ERROR: permission denied to drop role\n< 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >STATEMENT: DROP ROLE joe;\n\nIf audit logs are not generated when unsuccessful attempts to delete privileges/permissions occur, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to delete privileges occur.\n\nAll denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72947" do
  title "PostgreSQL must be able to generate audit records when privileges/permissions are retrieved."
  desc  "Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such information available through views or functions.\n\nThis requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000066"
  tag "gid": "V-72947"
  tag "rid": "SV-87599r1_rule"
  tag "stig_id": "PGS9-00-005500"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), check if pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf pgaudit is not found in the results, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), list all role memberships for the database:\n\n$ sudo su - postgres\n$ psql -c \"\\du\"\n\nNext, verify the query was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-01-28 19:43:12.126 UTC postgres postgres: >LOG: AUDIT: SESSION,1,1,READ,SELECT,,,\"SELECT r.rolname, r.rolsuper, r.rolinherit,\nr.rolcreaterole, r.rolcreatedb, r.rolcanlogin,\nr.rolconnlimit, r.rolvaliduntil,\nARRAY(SELECT b.rolname\nFROM pg_catalog.pg_auth_members m\nJOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)\nWHERE m.member = r.oid) as memberof\n, r.rolreplication\n, r.rolbypassrls\nFROM pg_catalog.pg_roles r\nORDER BY 1;\",<none>\n\nIf audit records are not produced, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log_catalog = 'on'\npgaudit.log = 'read'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72949" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000498-DB-000347"
  tag "gid": "V-72949"
  tag "rid": "SV-87601r1_rule"
  tag "stig_id": "PGS9-00-005600"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain \"pgaudit\", this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to modify categories of information.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. All denials are logged when logging is enabled.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72951" do
  title "PostgreSQL must generate audit records when unsuccessful accesses to objects occur."
  desc  "Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nIn an SQL environment, types of access include, but are not necessarily limited to:\n\nSELECT\nINSERT\nUPDATE\nDROP\nEXECUTE\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000507-DB-000357"
  tag "gid": "V-72951"
  tag "rid": "SV-87603r1_rule"
  tag "stig_id": "PGS9-00-005700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), create a schema, test_schema, create a table, test_table, within test_schema, and insert a value:\n\n$ sudo su - postgres\n$ psql -c \"CREATE SCHEMA test_schema\"\n$ psql -c \"CREATE TABLE test_schema.test_table(id INT)\"\n$ psql -c \"INSERT INTO test_schema.test_table(id) VALUES (0)\"\n\nNext, create a role 'bob' and attempt to SELECT, INSERT, UPDATE, and DROP from the test table: \n\n$ psql -c \"CREATE ROLE BOB\"\n$ psql -c \"SELECT * FROM test_schema.test_table\"\n$ psql -c \"INSERT INTO test_schema.test_table VALUES (0)\"\n$ psql -c \"UPDATE test_schema.test_table SET id = 1 WHERE id = 0\"\n$ psql -c \"DROP TABLE test_schema.test_table\"\n$ psql -c \"DROP SCHEMA test_schema\"\n\nNow, as the database administrator (shown here as \"postgres\"), review PostgreSQL/database security and audit settings to verify that audit records are created for unsuccessful attempts at the specified access to the specified objects:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n2016-03-30 17:23:41.254 EDT postgres postgres ERROR: permission denied for schema test_schema at character 15\n2016-03-30 17:23:41.254 EDT postgres postgres STATEMENT: SELECT * FROM test_schema.test_table;\n2016-03-30 17:23:53.973 EDT postgres postgres ERROR: permission denied for schema test_schema at character 13\n2016-03-30 17:23:53.973 EDT postgres postgres STATEMENT: INSERT INTO test_schema.test_table VALUES (0);\n2016-03-30 17:24:32.647 EDT postgres postgres ERROR: permission denied for schema test_schema at character 8\n2016-03-30 17:24:32.647 EDT postgres postgres STATEMENT: UPDATE test_schema.test_table SET id = 1 WHERE id = 0;\n2016-03-30 17:24:46.197 EDT postgres postgres ERROR: permission denied for schema test_schema\n2016-03-30 17:24:46.197 EDT postgres postgres STATEMENT: DROP TABLE test_schema.test_table;\n2016-03-30 17:24:51.582 EDT postgres postgres ERROR: must be owner of schema test_schema\n2016-03-30 17:24:51.582 EDT postgres postgres STATEMENT: DROP SCHEMA test_schema;\n\nIf any of the above steps did not create audit records for SELECT, INSERT, UPDATE, and DROP, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.\n\nAll errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72953" do
  title "PostgreSQL must generate audit records for all privileged activities or other system-level access."
  desc  "Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nSystem documentation should include a definition of the functionality considered privileged.\n\nA privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:\n\nCREATE\nALTER\nDROP\nGRANT\nREVOKE\n\nThere may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include:\n\nTRUNCATE TABLE;DELETE, or DELETE affecting more than n rows, for some n, or DELETE without a WHERE clause;\n\nUPDATE or UPDATE affecting more than n rows, for some n, or UPDATE without a WHERE clause;\n\nany SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.\n\nDepending on the capabilities of PostgreSQL and the design of the database and associated applications, audit logging may be achieved by means of DBMS auditing features, database triggers, other mechanisms, or a combination of these.\n\nNote: That it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000504-DB-000354"
  tag "gid": "V-72953"
  tag "rid": "SV-87605r1_rule"
  tag "stig_id": "PGS9-00-005800"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\nshared_preload_libraries = ‘pgaudit’\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72955" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000494-DB-000345"
  tag "gid": "V-72955"
  tag "rid": "SV-87607r1_rule"
  tag "stig_id": "PGS9-00-005900"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW pgaudit.log\"\n\nIf pgaudit.log does not contain, \"ddl, write, role\", this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to access categories of information.\n\nAll denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nWith `pgaudit` installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'ddl, write, role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-$9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72957" do
  title "PostgreSQL must be able to generate audit records when security objects are accessed."
  desc  "Changes to the security configuration must be tracked.\n\nThis requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.\n\nIn an SQL environment, types of access include, but are not necessarily limited to:\n\nCREATE\nSELECT\nINSERT\nUPDATE\nDELETE\nPREPARE\nEXECUTE\nALTER\nDRO."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000492-DB-000332"
  tag "gid": "V-72957"
  tag "rid": "SV-87609r1_rule"
  tag "stig_id": "PGS9-00-006000"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72959" do
  title "PostgreSQL must generate audit records when privileges/permissions are deleted."
  desc  "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.\n\nIn an SQL environment, deleting permissions is typically done via the REVOKE command."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000499-DB-000330"
  tag "gid": "V-72959"
  tag "rid": "SV-87611r1_rule"
  tag "stig_id": "PGS9-00-006100"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72961" do
  title "PostgreSQL must generate audit records when concurrent logons/connections by the same user from different workstations occur."
  desc  "For completeness of forensic analysis, it is necessary to track who logs on to PostgreSQL.\n\nConcurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.\n\n(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000506-DB-000353"
  tag "gid": "V-72961"
  tag "rid": "SV-87613r1_rule"
  tag "stig_id": "PGS9-00-006200"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify that log_connections and log_disconnections are enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_connections\"\n$ psql -c \"SHOW log_disconnections\"\n\nIf either is off, this is a finding.\n\nNext, verify that log_line_prefix contains sufficient information by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf log_line_prefix does not contain at least %m %u %d %c, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters as such:\n\nlog_connections = on\nlog_disconnections = on\nlog_line_prefix = '< %m %u %d %c: >'\n\nWhere:\n* %m is the time and date\n* %u is the username\n* %d is the database\n* %c is the session ID for the connection\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72963" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to delete security objects occur."
  desc  "The removal of security objects from the database/PostgreSQL would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000337"
  tag "gid": "V-72963"
  tag "rid": "SV-87615r1_rule"
  tag "stig_id": "PGS9-00-006300"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nConfigure PostgreSQL to produce audit records when unsuccessful attempts to delete security objects occur.\n\nAll errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72965" do
  title "PostgreSQL must generate audit records when privileges/permissions are modified."
  desc  "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.\n\nIn an SQL environment, modifying permissions is typically done via the GRANT and REVOKE commands."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000328"
  tag "gid": "V-72965"
  tag "rid": "SV-87617r1_rule"
  tag "stig_id": "PGS9-00-006400"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role is enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72969" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur."
  desc  "Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nSystem documentation should include a definition of the functionality considered privileged.\n\nA privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:\n\nCREATE\nALTER\nDROP\nGRANT\nREVOKE\n\nNote: That it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000504-DB-000355"
  tag "gid": "V-72969"
  tag "rid": "SV-87621r1_rule"
  tag "stig_id": "PGS9-00-006500"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), create the role bob by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob\"\n\nNext, change the current role to bob and attempt to execute privileged activity:\n\n$ psql -c \"CREATE ROLE stig_test SUPERUSER\"\n$ psql -c \"CREATE ROLE stig_test CREATEDB\"\n$ psql -c \"CREATE ROLE stig_test CREATEROLE\"\n$ psql -c \"CREATE ROLE stig_test CREATEUSER\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify that an audit event was produced (use the latest log):\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers\n< 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test SUPERUSER;\n< 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role\n< 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEDB;\n< 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role\n< 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEROLE;\n< 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers\n< 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEUSER;\n\nIf audit records are not produced, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to execute privileged SQL.\n\nAll denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72971" do
  title "PostgreSQL must generate audit records when security objects are modified."
  desc  "Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000334"
  tag "gid": "V-72971"
  tag "rid": "SV-87623r1_rule"
  tag "stig_id": "PGS9-00-006600"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the results does not contain `pgaudit`, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain `role`, `read`, `write`, and `ddl`, this is a finding.\n\nNext, verify that accessing the catalog is audited by running the following SQL:\n\n$ psql -c \"SHOW pgaudit.log_catalog\"\n\nIf log_catalog is not `on`, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nUsing `pgaudit` the DBMS (PostgreSQL) can be configured to audit these requests. See supplementary content `APPENDIX-B` for documentation on installing `pgaudit`.\n\nWith `pgaudit` installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log_catalog = 'on'\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72973" do
  title "PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is modified."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000498-DB-000346"
  tag "gid": "V-72973"
  tag "rid": "SV-87625r1_rule"
  tag "stig_id": "PGS9-00-006700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "If category tracking is not required in the database, this is not applicable.\n\nFirst, as the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain pgaudit, this is a finding.\n\nNext, verify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72975" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to modify privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.\n\nModifying permissions is done via the GRANT and REVOKE commands.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000329"
  tag "gid": "V-72975"
  tag "rid": "SV-87627r1_rule"
  tag "stig_id": "PGS9-00-006800"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), create a role 'bob' and a test table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob; CREATE TABLE test(id INT)\"\n\nNext, set current role to bob and attempt to modify privileges:\n\n$ psql -c \"SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;\"\n$ psql -c \"SET ROLE bob; REVOKE ALL PRIVILEGES ON test FROM bob\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the unsuccessful attempt was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test\n2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;\n2016-07-14 18:14:52.895 EDT postgres postgres ERROR: permission denied for relation test\n2016-07-14 18:14:52.895 EDT postgres postgres STATEMENT: REVOKE ALL PRIVILEGES ON test FROM bob;\n\nIf audit logs are not generated when unsuccessful attempts to modify privileges/permissions occur, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to modify privileges occur.\n\nAll denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72977" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.\n\nIn an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE command.\n\nTo aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000327"
  tag "gid": "V-72977"
  tag "rid": "SV-87629r1_rule"
  tag "stig_id": "PGS9-00-006900"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), create a role 'bob' and a test table by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"CREATE ROLE bob; CREATE TABLE test(id INT)\"\n\nNext, set current role to bob and attempt to modify privileges:\n\n$ psql -c \"SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;\"\n\nNow, as the database administrator (shown here as \"postgres\"), verify the unsuccessful attempt was logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test\n2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;\n\nIf audit logs are not generated when unsuccessful attempts to add privileges/permissions occur, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.\n\nAll denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72979" do
  title "PostgreSQL, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.\n\nA certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.\n\nDatabase Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-DB-000067"
  tag "gid": "V-72979"
  tag "rid": "SV-87631r1_rule"
  tag "stig_id": "PGS9-00-007000"
  tag "cci": "CCI-000185"
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo verify that a CRL file exists, as the database administrator (shown here as \"postgres\"), run the following:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl_crl_file\"\n\nIf this is not set to a CRL file, this is a finding.\n\nNext verify the existence of the CRL file by checking the directory set in postgresql.conf in the ssl_crl_file parameter from above:\n\nNote: If no directory is specified, then the CRL file should be located in the same directory as postgresql.conf (PGDATA).\n\nIf the CRL file does not exist, this is a finding.\n\nNext, verify that hostssl entries in pg_hba.conf have \"cert\" and \"clientcert=1\" enabled:\n\n$ sudo su - postgres\n$ grep hostssl ${PGDATA?}/postgresql.conf\n\nIf hostssl entries does not contain cert or clientcert=1, this is a finding.\n\nIf certificates are not being validated by performing RFC 5280-compliant certification path validation, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo configure PostgreSQL to use SSL, see supplementary content APPENDIX-G.\n\nTo generate a Certificate Revocation List, see the official Red Hat Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Update_Infrastructure/2.1/html/Administration_Guide/chap-Red_Hat_Update_Infrastructure-Administration_Guide-Certification_Revocation_List_CRL.html\n\nAs the database administrator (shown here as \"postgres\"), copy the CRL file into the data directory:\n\nFirst, as the system administrator, copy the CRL file into the PostgreSQL Data Directory:\n\n$ sudo cp root.crl ${PGDATA?}/root.crl\n\nAs the database administrator (shown here as \"postgres\"), set the ssl_crl_file parameter to the filename of the CRL:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nssl_crl_file = 'root.crl'\n\nNext, in pg_hba.conf, require ssl authentication:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/pg_hba.conf\nhostssl <database> <user> <address> cert clientcert=1\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72981" do
  title "PostgreSQL must maintain the confidentiality and integrity of information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.\n\nUse of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. \n\nWhen transmitting data, PostgreSQL, associated applications, and infrastructure must leverage transmission protection mechanisms.\n\nPostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c, while the name is misleading, this function enables only TLS encryption methods, not SSL.\n\nSee OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.htm."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000441-DB-000378"
  tag "gid": "V-72981"
  tag "rid": "SV-87633r1_rule"
  tag "stig_id": "PGS9-00-007200"
  tag "cci": "CCI-002420"
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "check": "If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.\n\nAs the database administrator (shown here as \"postgres\"), verify SSL is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl\"\n\nIf SSL is not enabled, this is a finding.\n\nIf PostgreSQL does not employ protective measures against unauthorized disclosure and modification during preparation for transmission, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nImplement protective measures against unauthorized disclosure and modification during preparation for transmission.\n\nTo configure PostgreSQL to use SSL, as a database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameter:\n\nssl = on\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-72983" do
  title "PostgreSQL must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components."
  desc  "Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within PostgreSQL (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.\n\nDoD has defined the list of events for which PostgreSQL will provide an audit record generation capability as the following: \n\n(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);\n(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and\n(iii) All account creation, modification, disabling, and termination actions.\n\nOrganizations may define additional events requiring continuous or ad hoc auditing."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000089-DB-000064"
  tag "gid": "V-72983"
  tag "rid": "SV-87635r1_rule"
  tag "stig_id": "PGS9-00-007400"
  tag "cci": "CCI-000169"
  tag "nist": ["AU-12 a", "Rev_4"]
  tag "check": "Check PostgreSQL auditing to determine whether organization-defined auditable events are being audited by the system.\n\nIf organization-defined auditable events are not being audited, this is a finding."
  tag "fix": "Configure PostgreSQL to generate audit records for at least the DoD minimum set of events.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
end
control "V-72985" do
  title "PostgreSQL must generate time stamps, for audit records and application data, with a minimum granularity of one second."
  desc  "Without sufficient granularity of time stamps, it is not possible to adequately determine the chronological order of records. \n\nTime stamps generated by PostgreSQL must include date and time. Granularity of time measurements refers to the precision available in time stamp values. Granularity coarser than one second is not sufficient for audit trail purposes. Time stamp values are typically presented with three or more decimal places of seconds; however, the actual granularity may be coarser than the apparent precision. For example, PostgreSQL will always return at least millisecond timestamps but it can be truncated using EXTRACT functions: SELECT EXTRACT(MINUTE FROM TIMESTAMP '2001-02-16 20:38:40');."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000375-DB-000323"
  tag "gid": "V-72985"
  tag "rid": "SV-87637r1_rule"
  tag "stig_id": "PGS9-00-007700"
  tag "cci": "CCI-001889"
  tag "nist": ["AU-8 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), verify the current log_line_prefix setting by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf log_line_prefix does not contain %m, this is a finding.\n\nNext check the logs to verify time stamps are being logged:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-02-23 12:53:33.947 EDT postgres postgres 570bd68d.3912 >LOG: connection authorized: user=postgres database=postgres\n< 2016-02-23 12:53:41.576 EDT postgres postgres 570bd68d.3912 >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE test_srg(id INT);,<none>\n< 2016-02-23 12:53:44.372 EDT postgres postgres 570bd68d.3912 >LOG: disconnection: session time: 0:00:10.426 user=postgres database=postgres host=[local]\n\nIf time stamps are not being logged, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nPostgreSQL will not log anything if logging is not enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log events with time stamps: \n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd %m to log_line_prefix to enable time stamps with milliseconds:\n\nlog_line_prefix = '< %m >'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72987" do
  title "PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.\n\nIdentifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.\n\n1) Linux's sudo and su feature enables a user (with sufficient OS privileges) to emulate another user, and it is the identity of the emulated user that is seen by PostgreSQL and logged in the audit trail. Therefore, care must be taken (outside of Postgresql) to restrict sudo/su to the minimum set of users necessary.\n\n2) PostgreSQL's SET ROLE feature enables a user (with sufficient PostgreSQL privileges) to emulate another user running statements under the permission set of the emulated user. In this case, it is the emulating user's identity, and not that of the emulated user, that gets logged in the audit trail. While this is definitely better than the other way around, ideally, both identities would be recorded."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000100-DB-000201"
  tag "gid": "V-72987"
  tag "rid": "SV-87639r1_rule"
  tag "stig_id": "PGS9-00-007800"
  tag "cci": "CCI-001487"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Check PostgreSQL settings and existing audit records to verify a user name associated with the event is being captured and stored with the audit records. If audit records exist without specific user information, this is a finding.\n\nFirst, as the database administrator (shown here as \"postgres\"), verify the current setting of log_line_prefix by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf log_line_prefix does not contain %m, %u, %d, %p, %r, %a, this is a finding."
  tag "fix": "Logging must be enabled in order to capture the identity of any user/subject or process associated with an event. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nTo enable username, database name, process ID, remote host/port and application name in logging, as the database administrator (shown here as \"postgres\"), edit the following in postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_line_prefix = '< %m %u %d %p %r %a >'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-72989" do
  title "PostgreSQL must implement NIST FIPS 140-2 validated cryptographic modules to generate and validate cryptographic hashes."
  desc  "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.\n\nFor detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000514-DB-000381"
  tag "gid": "V-72989"
  tag "rid": "SV-87641r1_rule"
  tag "stig_id": "PGS9-00-008000"
  tag "cci": "CCI-002450"
  tag "nist": ["SC-13", "Rev_4"]
  tag "check": "First, as the system administrator, run the following to see if FIPS is enabled:\n\n$ cat /proc/sys/crypto/fips_enabled\n\nIf fips_enabled is not 1, this is a finding."
  tag "fix": "Configure OpenSSL to be FIPS compliant.\n\nPostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, see the official RHEL Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-Federal_Standards_And_Regulations-Federal_Information_Processing_Standard.html\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-72991" do
  title "PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.\n\nIt is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.\n\nNSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of PostgreSQL with the encryption devices."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-72991"
  tag "rid": "SV-87643r1_rule"
  tag "stig_id": "PGS9-00-008100"
  tag "cci": "CCI-002450"
  tag "nist": ["SC-13", "Rev_4"]
  tag "check": "If PostgreSQL is deployed in an unclassified environment, this is not applicable (NA).\n\nIf PostgreSQL is not using NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.\n\nTo check if PostgreSQL is configured to use SSL, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl\"\n\nIf SSL is off, this is a finding.\n\nConsult network administration staff to determine whether the server is protected by NSA-approved encrypting devices. If not, this a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo configure PostgreSQL to use SSL, as a database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameter:\n\nssl = on\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.\n\nDeploy NSA-approved encrypting devices to protect the server on the network."
end
control "V-72993" do
  title "PostgreSQL must implement NIST FIPS 140-2 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.\n\nIt is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.\n\nFor detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000514-DB-000383"
  tag "gid": "V-72993"
  tag "rid": "SV-87645r1_rule"
  tag "stig_id": "PGS9-00-008200"
  tag "cci": "CCI-002450"
  tag "nist": ["SC-13", "Rev_4"]
  tag "check": "First, as the system administrator, run the following to see if FIPS is enabled:\n\n$ cat /proc/sys/crypto/fips_enabled\n\nIf fips_enabled is not 1, this is a finding."
  tag "fix": "Configure OpenSSL to be FIPS compliant.\n\nPostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, see the official RHEL Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-Federal_Standards_And_Regulations-Federal_Information_Processing_Standard.html\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-72995" do
  title "PostgreSQL must protect the confidentiality and integrity of all information at rest."
  desc  "This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. \n\nUser data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. \n\nIf the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000231-DB-000154"
  tag "gid": "V-72995"
  tag "rid": "SV-87647r1_rule"
  tag "stig_id": "PGS9-00-008300"
  tag "cci": "CCI-001199"
  tag "nist": ["SC-28", "Rev_4"]
  tag "check": "One possible way to encrypt data within PostgreSQL is to use the pgcrypto extension.\n\nTo check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as \"postgres\"), run the following command:\n\n$ sudo su - postgres\n$ psql -c \"SELECT * FROM pg_available_extensions where name='pgcrypto'\"\n\nIf data in the database requires encryption and pgcrypto is not available, this is a finding.\n\nIf disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of disk-level encryption. If this is required and is not found, this is a finding.\n\nIf controls do not exist or are not enabled, this is a finding."
  tag "fix": "Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.\n\nThe pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for documentation on installing pgcrypto.\n\nWith pgcrypto installed, it is possible to insert encrypted data into the database:\n\nINSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('xdes')));"
end
control "V-72997" do
  title "PostgreSQL must prohibit user installation of logic modules (functions, trigger procedures, views, etc.) without explicit privileged status."
  desc  "Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.\n\nPostgreSQL functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.\n\nPostgreSQL must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization). \n\nIn the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000378-DB-000365"
  tag "gid": "V-72997"
  tag "rid": "SV-87649r1_rule"
  tag "stig_id": "PGS9-00-008400"
  tag "cci": "CCI-001812"
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "check": "If PostgreSQL supports only software development, experimentation and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding.\n\nReview PostgreSQL and database security settings with respect to non-administrative users' ability to create, alter, or replace logic modules, to include but not necessarily only stored procedures, functions, triggers, and views.\n\nTo list the privileges for all tables and schemas, as the database administrator (shown here as \"postgres\"), run the following:\n\n$ sudo su - postgres\n$ psql -c \"\\dp\"\n$ psql -c \"\\dn+\"\n\nThe privileges are as follows:\n\nrolename=xxxx -- privileges granted to a role\n=xxxx -- privileges granted to PUBLIC\n\nr -- SELECT (\"read\")\nw -- UPDATE (\"write\")\na -- INSERT (\"append\")\nd -- DELETE\nD -- TRUNCATE\nx -- REFERENCES\nt -- TRIGGER\nX -- EXECUTE\nU -- USAGE\nC -- CREATE\nc -- CONNECT\nT -- TEMPORARY\narwdDxt -- ALL PRIVILEGES (for tables, varies for other objects)\n* -- grant option for preceding privilege\n\n/yyyy -- role that granted this privilege\n\nIf any such permissions exist and are not documented and approved, this is a finding."
  tag "fix": "Document and obtain approval for any non-administrative users who require the ability to create, alter or replace logic modules.\n\nImplement the approved permissions. Revoke any unapproved permissions."
end
control "V-72999" do
  title "PostgreSQL must separate user functionality (including user interface services) from database management functionality."
  desc  "Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. \n\nThe separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. \n\nAn example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. \n\nThis may include isolating the administrative interface on a different domain and with additional access controls.\n\nIf administrative functionality or information regarding PostgreSQL management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-DB-000122"
  tag "gid": "V-72999"
  tag "rid": "SV-87651r1_rule"
  tag "stig_id": "PGS9-00-008500"
  tag "cci": "CCI-001082"
  tag "nist": ["SC-2", "Rev_4"]
  tag "check": "Check PostgreSQL settings and vendor documentation to verify that administrative functionality is separate from user functionality.\n\nAs the database administrator (shown here as \"postgres\"), list all roles and permissions for the database:\n\n$ sudo su - postgres\n$ psql -c \"\\du\"\n\nIf any non-administrative role has the attribute \"Superuser\", \"Create role\", \"Create DB\" or \"Bypass RLS\", this is a finding.\n\nIf administrator and general user functionality are not separated either physically or logically, this is a finding."
  tag "fix": "Configure PostgreSQL to separate database administration and general user functionality.\n\nDo not grant superuser, create role, create db or bypass rls role attributes to users that do not require it.\n\nTo remove privileges, see the following example:\n\nALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;"
end
control "V-73001" do
  title "PostgreSQL must initiate session auditing upon startup."
  desc  "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time PostgreSQL is running."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000092-DB-000208"
  tag "gid": "V-73001"
  tag "rid": "SV-87653r1_rule"
  tag "stig_id": "PGS9-00-008600"
  tag "cci": "CCI-001464"
  tag "nist": ["AU-14 (1)", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), check the current settings by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf pgaudit is not in the current setting, this is a finding.\n\nAs the database administrator (shown here as \"postgres\"), check the current settings by running the following SQL:\n\n$ psql -c \"SHOW logging_destination\"\n\nIf stderr or syslog are not in the current setting, this is a finding."
  tag "fix": "Configure PostgreSQL to enable auditing.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nFor session logging we suggest using pgaudit. For instructions on how to setup pgaudit, see supplementary content APPENDIX-B."
end
control "V-73003" do
  title "PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components."
  desc  "PostgreSQLs handling data requiring \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation.\n\nSelection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). \n\nThe decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000428-DB-000386"
  tag "gid": "V-73003"
  tag "rid": "SV-87655r1_rule"
  tag "stig_id": "PGS9-00-008700"
  tag "cci": "CCI-002475"
  tag "nist": ["SC-28 (1)", "Rev_4"]
  tag "check": "Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.\n\nIf no information is identified as requiring such protection, this is not a finding.\n\nReview the configuration of PostgreSQL, operating system/file system, and additional software as relevant.\n\nIf any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding.\n\nOne possible way to encrypt data within PostgreSQL is to use pgcrypto extension.\n\nTo check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as \"postgres\"), run the following command:\n\n$ sudo su - postgres\n$ psql -c \"SELECT * FROM pg_available_extensions where name='pgcrypto'\"\n\nIf data in the database requires encryption and pgcrypto is not available, this is a finding.\n\nIf disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate filesystem or disk level encryption.\n\nIf this is required and is not found, this is a finding."
  tag "fix": "Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection.\n\nThe pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for documentation on installing pgcrypto.\n\nWith pgcrypto installed, it's possible to insert encrypted data into the database:\n\nINSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('md5')));"
end
control "V-73005" do
  title "PostgreSQL must produce audit records containing sufficient information to establish the sources (origins) of the events."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events relating to an incident.\n\nIn order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. \n\nIn addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.\n\nAssociating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000098-DB-000042"
  tag "gid": "V-73005"
  tag "rid": "SV-87657r1_rule"
  tag "stig_id": "PGS9-00-008800"
  tag "cci": "CCI-000133"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Check PostgreSQL settings and existing audit records to verify information specific to the source (origin) of the event is being captured and stored with audit records.\n\nAs the database administrator (usually postgres, check the current log_line_prefix and \"log_hostname\" setting by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n$ psql -c \"SHOW log_hostname\"\n\nFor a complete list of extra information that can be added to log_line_prefix, see the official documentation: https://www.postgresql.org/docs/current/static/runtime-config-logging.html#GUC-LOG-LINE-PREFIX\n\nIf the current settings do not provide enough information regarding the source of the event, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations can be made to log the source of an event.\n\nFirst, as the database administrator, edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\n###### Log Line Prefix\n\nExtra parameters can be added to the setting log_line_prefix to log source of event:\n\n# %a = application name\n# %u = user name\n# %d = database name\n# %r = remote host and port\n# %p = process ID\n# %m = timestamp with milliseconds\n\nFor example:\nlog_line_prefix = '< %m %a %u %d %r %p %m >'\n\n###### Log Hostname\n\nBy default only IP address is logged. To also log the hostname the following parameter can also be set in postgresql.conf:\n\nlog_hostname = on\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73007" do
  title "Unused database components, PostgreSQL software, and database objects must be removed."
  desc  "Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).\n\nIt is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. \n\nPostgreSQLs must adhere to the principles of least functionality by providing only essential capabilities."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-73007"
  tag "rid": "SV-87659r1_rule"
  tag "stig_id": "PGS9-00-008900"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "To get a list of all extensions installed, use the following commands:\n\n$ sudo su - postgres\n$ psql -c \"select * from pg_extension where extname != 'plpgsql';\"\"\n\nIf any extensions exist that are not approved, this is a finding."
  tag "fix": "To remove extensions, use the following commands:\n\n$ sudo su - postgres\n$ psql -c \"DROP EXTENSION <extension_name>\"\n\nNote: it is recommended that plpgsql not be removed."
end
control "V-73009" do
  title "Access to external executables must be disabled or restricted."
  desc  "Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). \n\nIt is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. \n\nApplications must adhere to the principles of least functionality by providing only essential capabilities.\n\nPostgreSQLs may spawn additional external processes to execute procedures that are defined in PostgreSQL but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than PostgreSQL and provide unauthorized access to the host system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000093"
  tag "gid": "V-73009"
  tag "rid": "SV-87661r1_rule"
  tag "stig_id": "PGS9-00-009100"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "PostgreSQL’s Copy command can interact with the underlying OS. Only superuser has access to this command.\n\nFirst, as the database administrator (shown here as \"postgres\"), run the following SQL to list all roles and their privileges:\n\n$ sudo su - postgres\n$ psql -x -c \"\\du\"\n\nIf any role has \"superuser\" that should not, this is a finding.\n\nIt is possible for an extension to contain code that could access external executables via SQL. To list all installed extensions, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -x -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL\"\n\nIf any extensions are installed that are not approved, this is a finding."
  tag "fix": "To remove superuser from a role, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\"\n\nTo remove extensions from PostgreSQL, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"DROP EXTENSION extension_name\""
end
control "V-73011" do
  title "Unused database components which are integrated in PostgreSQL and cannot be uninstalled must be disabled."
  desc  "Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). \n\nIt is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. \n\nPostgreSQLs must adhere to the principles of least functionality by providing only essential capabilities.\n\nUnused, unnecessary PostgreSQL components increase the attack vector for PostgreSQL by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "gid": "V-73011"
  tag "rid": "SV-87663r1_rule"
  tag "stig_id": "PGS9-00-009200"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "To list all installed packages, as the system administrator, run the following:\n\n# RHEL/CENT Systems\n$ sudo yum list installed | grep postgres\n\n# Debian Systems\n$ dpkg --get-selections | grep postgres\n\nIf any packages are installed that are not required, this is a finding."
  tag "fix": "To remove any unneeded executables, as the system administrator, run the following:\n\n# RHEL/CENT Systems\n$ sudo yum erase <package_name>\n\n# Debian Systems\n$ sudo apt-get remove <package_name>"
end
control "V-73013" do
  title "PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in process."
  desc  "Without the association of security labels to information, there is no basis for PostgreSQL to make security-related access-control decisions.\n\nSecurity labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. \n\nThese labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. \n\nOne example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.\n\nThe mechanism used to support security labeling may be the sepgsql feature of PostgreSQL, a third-party product, or custom application code."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000313-DB-000309"
  tag "gid": "V-73013"
  tag "rid": "SV-87665r1_rule"
  tag "stig_id": "PGS9-00-009400"
  tag "cci": "CCI-002263"
  tag "nist": ["AC-16 a", "Rev_4"]
  tag "check": "If security labeling is not required, this is not a finding.\n\nFirst, as the database administrator (shown here as \"postgres\"), run the following SQL against each table that requires security labels:\n\n$ sudo su - postgres\n$ psql -c \"\\d+ <schema_name>.<table_name>\"\n\nIf security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in process, this is a finding."
  tag "fix": "In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).\n\nRLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, see supplementary content APPENDIX-D."
end
control "V-73015" do
  title "If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.\n\nAuthentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.\n\nIn such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to PostgreSQL."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000171-DB-000074"
  tag "gid": "V-73015"
  tag "rid": "SV-87667r1_rule"
  tag "stig_id": "PGS9-00-009500"
  tag "cci": "CCI-000196"
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "To check if password encryption is enabled, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW password_encryption\"\n\nIf password_encryption is not on, this is a finding.\n\nNext, to identify if any passwords have been stored without being hashed and salted, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -x -c \"SELECT * FROM pg_shadow\"\n\nIf any password is in plaintext, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo enable password_encryption, as the database administrator, edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\npassword_encryption = on\n\nInstitute a policy of not using the \"WITH UNENCRYPTED PASSWORD\" option with the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the setting of the password_encryption configuration parameter.)\n\nAs the system administrator, restart the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl restart postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 restart"
end
control "V-73017" do
  title "PostgreSQL must enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s)."
  desc  "Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.\n\nWhen dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.\n\nAccordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000380-DB-000360"
  tag "gid": "V-73017"
  tag "rid": "SV-87669r1_rule"
  tag "stig_id": "PGS9-00-009600"
  tag "cci": "CCI-001813"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "To list all the permissions of individual roles, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\du\n\nIf any role has SUPERUSER that should not, this is a finding.\n\nNext, list all the permissions of databases and schemas by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\l\"\n$ psql -c \"\\dn+\"\n\nIf any database or schema has update (\"W\") or create (\"C\") privileges and should not, this is a finding."
  tag "fix": "Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).\n\nUse ALTER ROLE to remove accesses from roles:\n\n$ psql -c \"ALTER ROLE <role_name> NOSUPERUSER\"\n\nUse REVOKE to remove privileges from databases and schemas:\n\n$ psql -c \"REVOKE ALL PRIVILEGES ON <table> FROM <role_name>;"
end
control "V-73019" do
  title "PostgreSQL must protect against a user falsely repudiating having performed organization-defined actions."
  desc  "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. \n\nNon-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.\n\nIn designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables, and configuring PostgreSQL' audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to PostgreSQL, even where the application connects to PostgreSQL with a standard, shared account."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000080-DB-000063"
  tag "gid": "V-73019"
  tag "rid": "SV-87671r1_rule"
  tag "stig_id": "PGS9-00-009700"
  tag "cci": "CCI-000166"
  tag "nist": ["AU-10", "Rev_4"]
  tag "check": "First, as the database administrator, review the current log_line_prefix settings by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf log_line_prefix does not contain at least '< %m %a %u %d %r %p %m >', this is a finding.\n\nNext, review the current shared_preload_libraries' settings by running the following SQL:\n\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf shared_preload_libraries does not contain \"pgaudit\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nConfigure the database to supply additional auditing information to protect against a user falsely repudiating having performed organization-defined actions.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nModify the configuration of audit logs to include details identifying the individual user:\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nExtra parameters can be added to the setting log_line_prefix to identify the user:\n\nlog_line_prefix = '< %m %a %u %d %r %p %m >'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\nUse accounts assigned to individual users. Where the application connects to PostgreSQL using a standard, shared account, ensure that it also captures the individual user identification and passes it to PostgreSQL."
end
control "V-73021" do
  title "PostgreSQL must provide the capability for authorized users to capture, record, and log all content related to a user session."
  desc  "Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.\n\nTypically, this PostgreSQL capability would be used in conjunction with comparable monitoring of a user's online session, involving other software components such as operating systems, web servers and front-end user applications. The current requirement, however, deals specifically with PostgreSQL."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000093-DB-000052"
  tag "gid": "V-73021"
  tag "rid": "SV-87673r1_rule"
  tag "stig_id": "PGS9-00-009800"
  tag "cci": "CCI-001462"
  tag "nist": ["AU-14 (2)", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), verify pgaudit is installed by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf shared_preload_libraries does not contain pgaudit, this is a finding.\n\nNext, to verify connections and disconnections are logged, run the following SQL:\n\n$ psql -c \"SHOW log_connections\"\n$ psql -c \"SHOW log_disconnections\"\n\nIf log_connections and log_disconnections are off, this is a finding.\n\nNow, to verify that pgaudit is configured to log, run the following SQL:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf pgaudit.log does not contain ddl, role, read, write, this is a finding."
  tag "fix": "Configure the database capture, record, and log all content related to a user session.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nWith logging enabled, as the database administrator (shown here as \"postgres\"), enable log_connections and log_disconnections:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_connections = on\nlog_disconnections = on\n\nUsing pgaudit PostgreSQL can be configured to audit activity. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed, as a database administrator (shown here as \"postgres\"), enable which objects required for auditing a user's session:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\npgaudit.log = 'write, ddl, role, read, function';\npgaudit.log_relation = on; \n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73023" do
  title "The system must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity."
  desc  "Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to PostgreSQL on its own server will not be an issue. However, space will still be required on PostgreSQL server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.\n\nIf support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. \n\nThe appropriate support staff include, at a minimum, the ISSO and the DBA/SA."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000359-DB-000319"
  tag "gid": "V-73023"
  tag "rid": "SV-87675r1_rule"
  tag "stig_id": "PGS9-00-009900"
  tag "cci": "CCI-001855"
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "check": "Review system configuration.\n\nIf no script/tool is monitoring the partition for the PostgreSQL log directories, this is a finding.\n\nIf appropriate support staff are not notified immediately upon storage volume utilization reaching 75%, this is a finding."
  tag "fix": "Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75%.\n\nPostgreSQL does not monitor storage, however, it is possible to monitor storage with a script.\n\n##### Example Monitoring Script\n\n#!/bin/bash\n\nPGDATA=/var/lib/psql/9.5/data\nCURRENT=$(df ${PGDATA?} | grep / | awk '{ print $5}' | sed 's/%//g')\nTHRESHOLD=75\n\nif [ \"$CURRENT\" -gt \"$THRESHOLD\" ] ; then\nmail -s 'Disk Space Alert' mail@support.com << EOF\nThe data directory volume is almost full. Used: $CURRENT\n%EOF\nfi\n\nSchedule this script in cron to run around the clock."
end
control "V-73025" do
  title "PostgreSQL must provide the means for individuals in authorized roles to change the auditing to be performed on all application components, based on all selectable event criteria within organization-defined time thresholds."
  desc  "If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.\n\nThis requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real time, within minutes, or within hours."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000353-DB-000324"
  tag "gid": "V-73025"
  tag "rid": "SV-87677r1_rule"
  tag "stig_id": "PGS9-00-010000"
  tag "cci": "CCI-001914"
  tag "nist": ["AU-12 (3)", "Rev_4"]
  tag "check": "First, as the database administrator, check if pgaudit is present in shared_preload_libraries:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf pgaudit is not present in the result from the query, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nFor audit logging we suggest using pgaudit. For instructions on how to setup pgaudit, see supplementary content APPENDIX-B.\n\nAs a superuser (postgres), any pgaudit parameter can be changed in postgresql.conf. Configurations can only be changed by a superuser.\n\n### Example: Change Auditing To Log Any ROLE Statements\n\nNote: This will override any setting already configured.\n\nAlter the configuration to do role-based logging:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log = 'role'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\n### Example: Set An Auditing Role And Grant Privileges\n\nAn audit role can be configured and granted privileges to specific tables and columns that need logging.\n\n##### Create Test Table\n\n$ sudo su - postgres\n$ psql -c \"CREATE TABLE public.stig_audit_example(id INT, name TEXT, password TEXT);\"\n\n##### Define Auditing Role\n\nAs PostgreSQL superuser (such as postgres), add the following to postgresql.conf or any included configuration files.\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.role = 'auditor'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\nNext in PostgreSQL create a new role:\n\npostgres=# CREATE ROLE auditor;\npostgres=# GRANT select(password) ON public.stig_audit_example TO auditor;\n\nNote: This role is created with NOLOGIN privileges by default.\n\nNow any SELECT on the column password will be logged:\n\n$ sudo su - postgres\n$ psql -c \"SELECT password FROM public.stig_audit_example;\"\n$ cat ${PGDATA?}/pg_log/<latest_log>\n< 2016-01-28 16:46:09.038 UTC bob postgres: >LOG: AUDIT: OBJECT,6,1,READ,SELECT,TABLE,public.stig_audit_example,SELECT password FROM stig_audit_example;,<none>\n\n## Change Configurations During A Specific Timeframe\n\nDeploy PostgreSQL that allows audit configuration changes to take effect within the timeframe required by the application owner and without involving actions or events that the application owner rules unacceptable.\n\nCrontab can be used to do this.\n\nFor a specific audit role:\n\n# Grant specific audit privileges to an auditing role at 5 PM every day of the week, month, year at the 0 minute mark.\n0 5 * * * postgres /usr/bin/psql -c \"GRANT select(password) ON public.stig_audit_example TO auditor;\"\n# Revoke specific audit privileges to an auditing role at 5 PM every day of the week, month, year at the 0 minute mark.\n0 17 * * * postgres /usr/bin/psql -c \"REVOKE select(password) ON public.stig_audit_example FROM auditor;\""
end
control "V-73027" do
  title "PostgreSQL must require users to reauthenticate when organization-defined circumstances or situations require reauthentication."
  desc  "The DoD standard for authentication of an interactive user is the presentation of a Common Access Card (CAC) or other physical token bearing a valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled with a Personal Identification Number (PIN) to be entered by the user at the beginning of each session and whenever reauthentication is required.\n\nWithout reauthentication, users may access resources or perform tasks for which they do not have authorization.\n\nWhen applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user re-authenticate.\n\nIn addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:\n\n(i) When authenticators change;\n(ii) When roles change;\n(iii) When security categorized information systems change;\n(iv) When the execution of privileged functions occurs;\n(v) After a fixed period of time; or\n(vi) Periodically.\n\nWithin the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000389-DB-000372"
  tag "gid": "V-73027"
  tag "rid": "SV-87679r1_rule"
  tag "stig_id": "PGS9-00-010100"
  tag "cci": "CCI-002038"
  tag "nist": ["IA-11", "Rev_4"]
  tag "check": "Determine all situations where a user must re-authenticate. Check if the mechanisms that handle such situations use the following SQL:\n\nTo make a single user re-authenticate, the following must be present:\n\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'\n\nTo make all users re-authenticate, run the following:\n\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'\n\nIf the provided SQL does not force re-authentication, this is a finding."
  tag "fix": "Modify and/or configure PostgreSQL and related applications and tools so that users are always required to reauthenticate when changing role or escalating privileges.\n\nTo make a single user re-authenticate, the following must be present:\n\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'\n\nTo make all users re-authenticate, the following must be present:\n\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'"
end
control "V-73029" do
  title "PostgreSQL must enforce authorized access to all PKI private keys stored/utilized by PostgreSQL."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.\n\nIf the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where PostgreSQL-stored private keys are used to authenticate PostgreSQL to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man-in-the-middle attacks against PostgreSQL system and its clients.\n\nBoth the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.\n\nAll access to the private key(s) of PostgreSQL must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of PostgreSQL's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000176-DB-000068"
  tag "gid": "V-73029"
  tag "rid": "SV-87681r1_rule"
  tag "stig_id": "PGS9-00-010200"
  tag "cci": "CCI-000186"
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), verify the following settings:\n\nNote: If no specific directory given before the filename, the files are stored in PGDATA.\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl_ca_file\"\n$ psql -c \"SHOW ssl_cert_file\"\n$ psql -c \"SHOW ssl_crl_file\"\n$ psql -c \"SHOW ssl_key_file\"\n\nIf the directory these files are stored in is not protected, this is a finding."
  tag "fix": "Store all PostgreSQL PKI private keys in a FIPS 140-2 validated cryptographic module. Ensure access to PostgreSQL PKI private keys is restricted to only authenticated and authorized users.\n\nPostgreSQL private key(s) can be stored in $PGDATA directory, which is only accessible by the database owner (usually postgres, DBA) user. Do not allow access to this system account to unauthorized users.\n\nTo put the keys in a different directory, as the database administrator (shown here as \"postgres\"), set the following settings to a protected directory:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nssl_ca_file = \"/some/protected/directory/root.crt\"\nssl_crl_file = \"/some/protected/directory/root.crl\"\nssl_cert_file = \"/some/protected/directory/server.crt\"\nssl_key_file = \"/some/protected/directory/server.key\"\n\nNow, as the system administrator, restart the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl restartpostgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 restart\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-73031" do
  title "PostgreSQL must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions."
  desc  "Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. \n\nThe authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.\n\nThis requirement focuses on communications protection for PostgreSQL session rather than for the network packet."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000427-DB-000385"
  tag "gid": "V-73031"
  tag "rid": "SV-87683r1_rule"
  tag "stig_id": "PGS9-00-010300"
  tag "cci": "CCI-002470"
  tag "nist": ["SC-23 (5)", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), verify the following setting in postgresql.conf:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl_ca_file\"\n$ psql -c \"SHOW ssl_cert_file\"\n\nIf the database is not configured to used approved certificates, this is a finding."
  tag "fix": "Revoke trust in any certificates not issued by a DoD-approved certificate authority.\n\nConfigure PostgreSQL to accept only DoD and DoD-approved PKI end-entity certificates.\n\nTo configure PostgreSQL to accept approved CA's, see the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-73033" do
  title "PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.\n\nAssociating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. \n\nDatabase software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000095-DB-000039"
  tag "gid": "V-73033"
  tag "rid": "SV-87685r1_rule"
  tag "stig_id": "PGS9-00-010400"
  tag "cci": "CCI-000130"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), verify the current log_line_prefix setting in postgresql.conf:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nVerify that the current settings are appropriate for the organization.\n\nThe following is what is possible for logged information:\n\n# %a = application name\n# %u = user name\n# %d = database name\n# %r = remote host and port\n# %h = remote host\n# %p = process ID\n# %t = timestamp without milliseconds\n# %m = timestamp with milliseconds\n# %i = command tag\n# %e = SQL state\n# %c = session ID\n# %l = session line number\n# %s = session start timestamp\n# %v = virtual transaction ID\n# %x = transaction ID (0 if none)\n# %q = stop here in non-session\n# processes\n\nIf the audit record does not log events required by the organization, this is a finding.\n\nNext, verify the current settings of log_connections and log_disconnections by running the following SQL:\n\n$ psql -c \"SHOW log_connections\"\n$ psql -c \"SHOW log_disconnections\"\n\nIf both settings are off, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log connections, date/time, username and session identifier.\n\nFirst, edit the postgresql.conf file as a privileged user:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters based on the organization's needs (minimum requirements are as follows):\n\nlog_connections = on\nlog_disconnections = on\nlog_line_prefix = '< %m %u %d %c: >'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73035" do
  title "PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components."
  desc  "PostgreSQLs handling data requiring \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation.\n\nSelection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). \n\nThe decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000429-DB-000387"
  tag "gid": "V-73035"
  tag "rid": "SV-87687r1_rule"
  tag "stig_id": "PGS9-00-010500"
  tag "cci": "CCI-002476"
  tag "nist": ["SC-28 (1)", "Rev_4"]
  tag "check": "To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as \"postgres\"), run the following command:\n\n$ sudo su - postgres\n$ psql -c \"SELECT * FROM pg_available_extensions where name='pgcrypto'\"\n\nIf data in the database requires encryption and pgcrypto is not available, this is a finding.\n\nIf a disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of filesystem and/or disk-level encryption. If this is required and is not found, this is a finding."
  tag "fix": "Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.\n\nSecure the premises, equipment, and media to provide the required level of physical protection.\n\nThe pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for documentation on installing pgcrypto.\n\nWith pgcrypto installed, it is possible to insert encrypted data into the database:\n\nINSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('md5')));"
end
control "V-73037" do
  title "PostgreSQL must invalidate session identifiers upon user logout or other session termination."
  desc  "Captured sessions can be reused in \"replay\" attacks. This requirement limits the ability of adversaries to capture and continue to employ previously valid session IDs.\n\nThis requirement focuses on communications protection for PostgreSQL session rather than for the network packet. The intent of this control is to establish grounds for confidence at each end of a communications session in the ongoing identity of the other party and in the validity of the information being transmitted. \n\nSession IDs are tokens generated by PostgreSQLs to uniquely identify a user's (or process's) session. DBMSs will make access decisions and execute logic based on the session ID.\n\nUnique session IDs help to reduce predictability of said identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of. information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. \n\nWhen a user logs out, or when any other session termination event occurs, PostgreSQL must terminate the user session(s) to minimize the potential for sessions to be hijacked."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000220-DB-000149"
  tag "gid": "V-73037"
  tag "rid": "SV-87689r1_rule"
  tag "stig_id": "PGS9-00-010600"
  tag "cci": "CCI-001185"
  tag "nist": ["SC-23 (1)", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW tcp_keepalives_idle\"\n$ psql -c \"SHOW tcp_keepalives_interval\"\n$ psql -c \"SHOW tcp_keepalives_count\"\n$ psql -c \"SHOW statement_timeout\"\n\nIf these settings are not set, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nAs the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi $PGDATA/postgresql.conf\n\nSet the following parameters to organizational requirements:\n\nstatement_timeout = 10000 #milliseconds\ntcp_keepalives_idle = 10 # seconds\ntcp_keepalives_interval = 10 # seconds\ntcp_keepalives_count = 10\n\nNow, as the system administrator, restart the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl restart postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 restart"
end
control "V-73039" do
  title "PostgreSQL must protect its audit features from unauthorized access."
  desc  "Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. \n\nDepending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. \n\nApplications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.\n\nAudit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. \n\nIf an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-73039"
  tag "rid": "SV-87691r1_rule"
  tag "stig_id": "PGS9-00-010700"
  tag "cci": "CCI-001493"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA. Only the database owner and superuser can alter configuration of PostgreSQL.\n\nMake sure the pg_log directory are owned by postgres user and group:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}/pg_log\n\nIf pg_log is not owned by the database owner, this is a finding.\n\nMake sure the data directory are owned by postgres user and group.\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}\n\nIf PGDATA is not owned by the database owner, this is a finding.\n\nMake sure pgaudit installation is owned by root:\n\n$ sudo su - postgres\n$ ls -la /usr/pgsql-9.5/share/contrib/pgaudit\n\nIf pgaudit installation is not owned by root, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), run the following SQL to list all roles and their privileges:\n\n$ sudo su - postgres\n$ psql -x -c \"\\du\"\n\nIf any role has \"superuser\" that should not, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nIf pg_log or data directory are not owned by postgres user and group, configure them as follows:\n\n$ sudo chown -R postgres:postgres ${PGDATA?}\n\nIf the pgaudit installation is not owned by root user and group, configure it as follows:\n\n$ sudo chown -R root:root /usr/pgsql-9.5/share/contrib/pgaudit.\n\nTo remove superuser from a role, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\""
end
control "V-73041" do
  title "PostgreSQL must produce audit records containing time stamps to establish when the events occurred."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.\n\nIn order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the date and time when events occurred.\n\nAssociating the date and time with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. \n\nDatabase software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when specific actions were performed. This requires the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000096-DB-000040"
  tag "gid": "V-73041"
  tag "rid": "SV-87693r1_rule"
  tag "stig_id": "PGS9-00-011100"
  tag "cci": "CCI-000131"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "As the database administrator (usually postgres, run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf the query result does not contain \"%m\", this is a finding."
  tag "fix": "Logging must be enabled in order to capture timestamps. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log events with timestamps:\n\nFirst, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd %m to log_line_prefix to enable timestamps with milliseconds:\n\nlog_line_prefix = '< %m >'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73043" do
  title "PostgreSQL must protect its audit features from unauthorized removal."
  desc  "Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.\n\nApplications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.\n\nAudit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000123-DB-000204"
  tag "gid": "V-73043"
  tag "rid": "SV-87695r1_rule"
  tag "stig_id": "PGS9-00-011200"
  tag "cci": "CCI-001495"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), verify the permissions of PGDATA:\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}\n\nIf PGDATA is not owned by postgres:postgres or if files can be accessed by others, this is a finding.\n\nAs the system administrator, verify the permissions of pgsql shared objects and compiled binaries:\n\n$ ls -la /usr/pgsql-9.5/bin/\n$ ls -la /usr/pgsql-9.5/share\n$ ls -la /usr/pgsql-9.5/include\n\nIf any of these are not owned by root:root, this is a finding."
  tag "fix": "As the system administrator, change the permissions of PGDATA:\n\n$ sudo chown -R postgres:postgres ${PGDATA?}\n$ sudo chmod 700 ${PGDATA?}\n\nAs the system administrator, change the permissions of pgsql:\n\n$ sudo chown -R root:root /usr/pgsql-9.5/share/contrib/pgaudit"
end
control "V-73045" do
  title "PostgreSQL must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems."
  desc  "Information stored in one location is vulnerable to accidental or incidental deletion or alteration.\n\nOff-loading is a common process in information systems with limited audit storage capacity. \n\nPostgreSQL may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000515-DB-000318"
  tag "gid": "V-73045"
  tag "rid": "SV-87697r1_rule"
  tag "stig_id": "PGS9-00-011300"
  tag "cci": "CCI-001851"
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"), ensure PostgreSQL uses syslog by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_destination\"\n\nIf log_destination is not syslog, this is a finding.\n\nNext, as the database administrator, check which log facility is configured by running the following SQL:\n\n$ psql -c \"SHOW syslog_facility\" \n\nCheck with the organization to see how syslog facilities are defined in their organization.\n\nIf the wrong facility is configured, this is a finding.\n\nIf PostgreSQL does not have a continuous network connection to the centralized log management system, and PostgreSQL audit records are not transferred to the centralized log management system weekly or more often, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nConfigure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near-real time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nWith logging enabled, as the database administrator (shown here as \"postgres\"), configure the follow parameters in postgresql.conf (the example uses the default values - tailor for environment):\n\nNote: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_destination = 'syslog'\nsyslog_facility = 'LOCAL0'\nsyslog_ident = 'postgres'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73047" do
  title "PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values."
  desc  "One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.\n\nThe preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.\n\nHowever, it is recognized that available PostgreSQL products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-DB-000384"
  tag "gid": "V-73047"
  tag "rid": "SV-87699r1_rule"
  tag "stig_id": "PGS9-00-011400"
  tag "cci": "CCI-001188"
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "check": "To check if PostgreSQL is configured to use ssl, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW ssl\"\n\nIf this is not set to on, this is a finding."
  tag "fix": "To configure PostgreSQL to use SSL, as a database owner (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameter:\n\nssl = on\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.\n\nFor further SSL configurations, see the official documentation: https://www.postgresql.org/docs/current/static/ssl-tcp.html"
end
control "V-73049" do
  title "PostgreSQL must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users)."
  desc  "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. \n\nOrganizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:\n\n(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and \n(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-73049"
  tag "rid": "SV-87701r1_rule"
  tag "stig_id": "PGS9-00-011500"
  tag "cci": "CCI-000764"
  tag "nist": ["IA-2", "Rev_4"]
  tag "check": "Review PostgreSQL settings to determine whether organizational users are uniquely identified and authenticated when logging on/connecting to the system.\n\nTo list all roles in the database, as the database administrator (shown here as \"postgres\"), run the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"\\du\"\n\nIf organizational users are not uniquely identified and authenticated, this is a finding.\n\nNext, as the database administrator (shown here as \"postgres\"), verify the current pg_hba.conf authentication settings:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_hba.conf\n\nIf every role does not have unique authentication requirements, this is a finding.\n\nIf accounts are determined to be shared, determine if individuals are first individually authenticated. If individuals are not individually authenticated before using the shared account, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nConfigure PostgreSQL settings to uniquely identify and authenticate all organizational users who log on/connect to the system.\n\nTo create roles, use the following SQL:\n\nCREATE ROLE <role_name> [OPTIONS]\n\nFor more information on CREATE ROLE, see the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html\n\nFor each role created, the database administrator can specify database authentication by editing pg_hba.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/pg_hba.conf\n\nAn example pg_hba entry looks like this:\n\n# TYPE DATABASE USER ADDRESS METHOD\nhost test_db bob 192.168.0.0/16 md5\n\nFor more information on pg_hba.conf, see the official documentation: https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html"
end
control "V-73051" do
  title "PostgreSQL must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect."
  desc  "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. \n\nSession termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. \n\nConditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.\n\nThis capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-DB-000305"
  tag "gid": "V-73051"
  tag "rid": "SV-87703r1_rule"
  tag "stig_id": "PGS9-00-011600"
  tag "cci": "CCI-002361"
  tag "nist": ["AC-12", "Rev_4"]
  tag "check": "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.\n\nIf the documentation requires automatic session termination, but PostgreSQL is not configured accordingly, this is a finding."
  tag "fix": "Configure PostgreSQL to automatically terminate a user session after organization-defined conditions or trigger events requiring session termination.\n\nExamples follow.\n\n### Change a role to nologin and disconnect the user\n\nALTER ROLE '<username>' NOLOGIN;\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE username='<username>';\n\n### Disconnecting users during a specific time range\nSee supplementary content APPENDIX-A for a bash script for this example.\n\nThe script found in APPENDIX-A using the -l command can disable all users with rolcanlogin=t from logging in. The script keeps track of who it disables in a .restore_login file. After the specified time is over, the same script can be run with the -r command to restore all login connections. \n\nThis script would be added to a cron job:\n\n# lock at 5 am every day of the week, month, year at the 0 minute mark.\n0 5 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -l\n# restore at 5 pm every day of the week, month, year at the 0 minute mark.\n0 17 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -r"
end
control "V-73053" do
  title "PostgreSQL must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures."
  desc  "Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. \n\nSystem documentation should include a definition of the functionality considered privileged.\n\nDepending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.\n\nA privileged function in PostgreSQL/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to: \n\nCREATE\nALTER\nDROP\nGRANT\nREVOKE\n\nThere may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples include:\n\nTRUNCATE TABLE;\nDELETE, or\nDELETE affecting more than n rows, for some n, or\nDELETE without a WHERE clause;\n\nUPDATE or\nUPDATE affecting more than n rows, for some n, or\nUPDATE without a WHERE clause;\n\nany SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.\n\nDepending on the capabilities of PostgreSQL and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these.\n\nHowever, the use of procedural languages within PostgreSQL, such as pl/R and pl/Python, introduce security risk. Any user on the PostgreSQL who is granted access to pl/R or pl/Python is able to run UDFs to escalate privileges and perform unintended functions. Procedural languages such as pl/Perl and pl/Java have \"untrusted\" mode of operation, which do not allow a non-privileged PostgreSQL user to escalate privileges or perform actions as a database administrator."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000340-DB-000304"
  tag "gid": "V-73053"
  tag "rid": "SV-87705r1_rule"
  tag "stig_id": "PGS9-00-011700"
  tag "cci": "CCI-002235"
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "check": "Review the system documentation to obtain the definition of the PostgreSQL functionality considered privileged in the context of the system in question.\n\nReview the PostgreSQL security configuration and/or other means used to protect privileged functionality from unauthorized use.\n\nIf the configuration does not protect all of the actions defined as privileged, this is a finding.\n\nIf PostgreSQL instance uses procedural languages, such as pl/Python or pl/R, without AO authorization, this is a finding."
  tag "fix": "Configure PostgreSQL security to protect all privileged functionality. \n\nIf pl/R and pl/Python are used, document their intended use, document users that have access to pl/R and pl/Python, as well as their business use case, such as data-analytics or data-mining. Because of the risks associated with using pl/R and pl/Python, their use must have AO risk acceptance.\n\nTo remove unwanted extensions, use:\n\nDROP EXTENSION <extension_name>\n\nTo remove unwanted privileges from a role, use the REVOKE command. \n\nSee the PostgreSQL documentation for more details: http://www.postgresql.org/docs/current/static/sql-revoke.html"
end
control "V-73055" do
  title "PostgreSQL must map the PKI-authenticated identity to an associated user account."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to PostgreSQL user account for the authenticated identity to be meaningful to PostgreSQL and useful for authorization decisions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000177-DB-000069"
  tag "gid": "V-73055"
  tag "rid": "SV-87707r1_rule"
  tag "stig_id": "PGS9-00-011800"
  tag "cci": "CCI-000187"
  tag "nist": ["IA-5 (2) (c)", "Rev_4"]
  tag "check": "The cn (Common Name) attribute of the certificate will be compared to the requested database user name, and if they match the login will be allowed. \n\nTo check the cn of the certificate, using openssl, do the following:\n\n$ openssl x509 -noout -subject -in client_cert\n\nIf the cn does not match the users listed in PostgreSQL and no user mapping is used, this is a finding.\n\nUser name mapping can be used to allow cn to be different from the database user name. If User Name Maps are used, run the following as the database administrator (shown here as \"postgres\"), to get a list of maps used for authentication:\n\n$ sudo su - postgres\n$ grep \"map\" ${PGDATA?}/pg_hba.conf\n\nWith the names of the maps used, check those maps against the user name mappings in pg_ident.conf:\n\n$ sudo su - postgres\n$ cat ${PGDATA?}/pg_ident.conf\n\nIf user accounts are not being mapped to authenticated identities, this is a finding.\n\nIf the cn and the username mapping do not match, this is a finding."
  tag "fix": "Configure PostgreSQL to map authenticated identities directly to PostgreSQL user accounts.\n\nFor information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-73057" do
  title "Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy."
  desc  "Applications, including PostgreSQLs, must prevent unauthorized and unintended information transfer via shared system resources. \n\nData used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, to include the conditions under which such transfer may take place, where the copies may reside, and the rules for ensuring sensitive data are not exposed.\n\nCopies of sensitive data must not be misplaced or left in a temporary location without the proper controls."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000128"
  tag "gid": "V-73057"
  tag "rid": "SV-87709r1_rule"
  tag "stig_id": "PGS9-00-011900"
  tag "cci": "CCI-001090"
  tag "nist": ["SC-4", "Rev_4"]
  tag "check": "Review the procedures for the refreshing of development/test data from production.\n\nReview any scripts or code that exists for the movement of production data to development/test systems, or to any other location or for any other purpose.\n\nVerify that copies of production data are not left in unprotected locations. \n\nIf the code that exists for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding."
  tag "fix": "Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations."
end
control "V-73059" do
  title "Access to database files must be limited to relevant processes and to authorized, administrative users."
  desc  "Applications, including PostgreSQLs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000374"
  tag "gid": "V-73059"
  tag "rid": "SV-87711r1_rule"
  tag "stig_id": "PGS9-00-012000"
  tag "cci": "CCI-001090"
  tag "nist": ["SC-4", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nReview the permissions granted to users by the operating system/file system on the database files, database log files and database backup files. \n\nTo verify that all files are owned by the database administrator and have the correct permissions, run the following as the database administrator (shown here as \"postgres\"):\n\n$ sudo su - postgres\n$ ls -lR ${PGDATA?}\n\nIf any files are not owned by the database administrator or allow anyone but the database administrator to read/write/execute, this is a finding.\n\nIf any user/role who is not an authorized system administrator with a need-to-know or database administrator with a need-to-know, or a system account for running PostgreSQL processes, is permitted to read/view any of these files, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nConfigure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.\n\nAny files (for example: extra configuration files) created in PGDATA must be owned by the database administrator, with only owner permissions to read, write, and execute."
end
control "V-73061" do
  title "PostgreSQL must protect its audit configuration from unauthorized modification."
  desc  "Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.\n\nApplications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.\n\nAudit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000122-DB-000203"
  tag "gid": "V-73061"
  tag "rid": "SV-87713r1_rule"
  tag "stig_id": "PGS9-00-012200"
  tag "cci": "CCI-001494"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "All configurations for auditing and logging can be found in the postgresql.conf configuration file. By default, this file is owned by the database administrator account. \n\nTo check that the permissions of the postgresql.conf are owned by the database administrator with permissions of 0600, run the following as the database administrator (shown here as \"postgres\"):\n\n$ sudo su - postgres\n$ ls -la ${PGDATA?}\n\nIf postgresql.conf is not owned by the database administrator or does not have 0600 permissions, this is a finding.\n\n#### stderr Logging\n\nTo check that logs are created with 0600 permissions, check the postgresql.conf file for the following setting:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_file_mode\"\n\nIf permissions are not 0600, this is a finding.\n\n#### syslog Logging\n\nIf PostgreSQL is configured to use syslog, verify that the logs are owned by root and have 0600 permissions. If they are not, this is a finding."
  tag "fix": "Apply or modify access controls and permissions (both within PostgreSQL and in the file system/operating system) to tools used to view or modify audit log data. Tools must be configurable by authorized personnel only.\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\nlog_file_mode = 0600\n\nNext, as the database administrator (shown here as \"postgres\"), change the ownership and permissions of configuration files in PGDATA:\n\n$ sudo su - postgres\n$ chown postgres:postgres ${PGDATA?}/*.conf\n$ chmod 0600 ${PGDATA?}/*.conf"
end
control "V-73063" do
  title "PostgreSQL must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations."
  desc  "Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.\n\nApplications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.\n\nThe security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.\n\nNSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-73063"
  tag "rid": "SV-87715r1_rule"
  tag "stig_id": "PGS9-00-012300"
  tag "cci": "CCI-000803"
  tag "nist": ["IA-7", "Rev_4"]
  tag "check": "As the system administrator, run the following:\n\n$ openssl version\n\nIf \"fips\" is not included in the openssl version, this is a finding."
  tag "fix": "Configure OpenSSL to meet FIPS Compliance using the following documentation in section 9.1:\n\nhttp://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf\n\nFor more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
end
control "V-73065" do
  title "Audit records must be generated when categorized information (e.g., classification levels/security levels) is deleted."
  desc  "Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.\n\nFor detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000502-DB-000348"
  tag "gid": "V-73065"
  tag "rid": "SV-87717r1_rule"
  tag "stig_id": "PGS9-00-012500"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "As the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain \"pgaudit\", this is a finding.\n\nVerify that role, read, write and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations can be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73067" do
  title "PostgreSQL must generate audit records when successful accesses to objects occur."
  desc  "Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.\n\nIn an SQL environment, types of access include, but are not necessarily limited to:\n\nSELECT\nINSERT\nUPDATE\nDELETE\nEXECUT."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000507-DB-000356"
  tag "gid": "V-73067"
  tag "rid": "SV-87719r1_rule"
  tag "stig_id": "PGS9-00-012600"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "As the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain \"pgaudit\", this is a finding.\n\nVerify that role, read, write, and ddl auditing are enabled:\n\n$ psql -c \"SHOW pgaudit.log\"\n\nIf the output does not contain read and write, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nIf logging is enabled the following configurations must be made to log unsuccessful connections, date/time, username and session identifier.\n\nAs the database administrator (shown here as \"postgres\"), edit postgresql.conf:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nEdit the following parameters:\n\nlog_connections = on\nlog_line_prefix = '< %m %u %c: >'\npgaudit.log = 'read, write'\n\nWhere:\n* %m is the time and date\n* %u is the username\n* %c is the session ID for the connection\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73069" do
  title "PostgreSQL must generate audit records for all direct access to the database(s)."
  desc  "In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000508-DB-000358"
  tag "gid": "V-73069"
  tag "rid": "SV-87721r1_rule"
  tag "stig_id": "PGS9-00-012700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "As the database administrator, verify pgaudit is enabled by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW shared_preload_libraries\"\n\nIf the output does not contain \"pgaudit\", this is a finding.\n\nVerify that connections and disconnections are being logged by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_connections\"\n$ psql -c \"SHOW log_disconnections\"\n\nIf the output does not contain \"on\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nUsing pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.\n\nWith pgaudit installed the following configurations should be made:\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nAdd the following parameters (or edit existing parameters):\n\npgaudit.log='ddl, role, read, write'\nlog_connections='on'\nlog_disconnections='on'\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
control "V-73071" do
  title "The DBMS must be configured on a platform that has a NIST certified FIPS 140-2 installation of OpenSSL."
  desc  "Postgres uses OpenSSL for the underlying encryption layer. Currently only Red Hat Enterprise Linux is certified as a FIPS 140-2 distribution of OpenSSL. For other operating systems, users must obtain or build their own FIPS 140-2 OpenSSL libraries."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-73071"
  tag "rid": "SV-87723r1_rule"
  tag "stig_id": "PGS9-00-012800"
  tag "cci": "CCI-000803"
  tag "nist": ["IA-7", "Rev_4"]
  tag "check": "If the deployment incorporates a custom build of the operating system and Postgres guaranteeing the use of FIPS 140-2- compliant OpenSSL, this is not a finding.\n\nIf the Postgres Plus Advanced Server is not installed on Red Hat Enterprise Linux (RHEL), this is a finding.\n\nIf FIPS encryption is not enabled, this is a finding."
  tag "fix": "Install Postgres with FIPS-compliant cryptography enabled on RHEL; or by other means ensure that FIPS 140-2 certified OpenSSL libraries are used by the DBMS."
end
control "V-73123" do
  title "PostgreSQL must produce audit records containing sufficient information to establish where the events occurred."
  desc  "Information system auditing capability is critical for accurate forensic analysis. Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.\n\nIn order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. \n\nAssociating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000097-DB-000041"
  tag "gid": "V-73123"
  tag "rid": "SV-87775r1_rule"
  tag "stig_id": "PGS9-00-007100"
  tag "cci": "CCI-000132"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nFirst, as the database administrator (shown here as \"postgres\"), check the current log_line_prefix setting by running the following SQL:\n\n$ sudo su - postgres\n$ psql -c \"SHOW log_line_prefix\"\n\nIf log_line_prefix does not contain %m %u %d %s, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.\n\nTo check that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.\n\nFirst edit the postgresql.conf file as the database administrator (shown here as \"postgres\"):\n\n$ sudo su - postgres\n$ vi ${PGDATA?}/postgresql.conf\n\nExtra parameters can be added to the setting log_line_prefix to log application related information:\n\n# %a = application name\n# %u = user name\n# %d = database name\n# %r = remote host and port\n# %p = process ID\n# %m = timestamp with milliseconds\n# %i = command tag\n# %s = session startup\n# %e = SQL state\n\nFor example:\n\nlog_line_prefix = '< %m %a %u %d %r %p %i %e %s>’\n\nNow, as the system administrator, reload the server with the new configuration:\n\n# SYSTEMD SERVER ONLY\n$ sudo systemctl reload postgresql-9.5\n\n# INITD SERVER ONLY\n$ sudo service postgresql-9.5 reload"
end
