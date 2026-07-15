# Findings

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 38 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 16 enabled certificate templates
[*] Trying to get CA configuration for 'ESSOS-CA' via CSRA
[*] Got CA configuration for 'ESSOS-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : ESSOS-CA
    DNS Name                            : braavos.essos.local
    Certificate Subject                 : CN=ESSOS-CA, DC=essos, DC=local
    Certificate Serial Number           : 5A6322B09CA5F896466B2BF0E23762A3
    Certificate Validity Start          : 2024-12-18 11:11:18+00:00
    Certificate Validity End            : 2029-12-18 11:21:17+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : ESSOS.LOCAL\Administrators
      Access Rights
        ManageCertificates              : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        ManageCa                        : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        Enroll                          : ESSOS.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
Certificate Templates
  0
    Template Name                       : ESC4
    Display Name                        : ESC4
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Code Signing
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : 'ESSOS.LOCAL\\khal.drogo' has dangerous permissions
  1
    Template Name                       : ESC3-CRA
    Display Name                        : ESC3-CRA
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  2
    Template Name                       : ESC2
    Display Name                        : ESC2
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Any Purpose
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC2                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template can be used for any purpose
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  3
    Template Name                       : ESC1
    Display Name                        : ESC1
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC1                              : 'ESSOS.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
      ```