#Configuration file parameter information:
Listenport 
  -Description: port the http(s) server will bind to for servicing requests
  -Default: 8080

LDAPServer
  -Description: Hostname or IP of ldap server, (Uses tcp dial, if multiple IP addresses are returned it will try each one until a successful connection is made)
  -Default: localhost

LDAPPort
  -Description: Port ldap server is listening on.
  -Default: 389

LDAPSearchBase
  -Description: Search base used during ldap queries.
  -Default: dc=example,dc=net

LDAPSearchFilter
  -Description: The application uses this search filter during get roles and validate user, filter needs to return one or less values. For Active directoty a minimal
 proper filter would be (samAccountName=%s) '%s' is replaced with the value provided in the username header.
  -Default: (uid=%s)

LDAPBindUsername 
  -Description: Account application binds with to lookup role and other information
  -Default: cn=Directory Manager

LDAPBindPassword 
  -Description: Password for LDAPBindUsername
  -Default: changit

UsernameHeader
  -Description: Name of Header attribute where username will be assigned as the value.
  -Default: REMOTE_USER

PasswordHeader
  -Description: Name of Header attribute where password will be assigned as the value.
  -Default: PASSWORD

RoleNameHeader 
  -Description: Name of Header attribute where role name will be assigned as the value.
  -Default: ROLE_NAME

VerifyPassword
  -Description: Set to false if you do not which to attempt a bind with the username header value and password header value to validate user
 Helpful if you just wish to validate information in ldap but perhaps use certficate or other authentication mechanisms
  -Default: true

RoleAttributeName
  -Description: Attribute name where roles are assigned
  -Default: memberOf

UsernameAttribute
  -Description: Attribute name the username value is assigned (Active Directory uses samAccountName)
  -Default: uid

UseTLS
  -Description: Set to true if to use TLS, used to secure from passing password information over network in plain text. TLSCert and TLSKey required if set to true
  -Default: false

TLSCert
  -Description: Path to x509 certificate file
  -Default: cert.pem

TLSKey: 
  -Description: Path to x509 key file
  -Default: key.pem