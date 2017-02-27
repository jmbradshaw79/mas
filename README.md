# mas - micro auth service
This is an attempt at creating a micro service that can provide a simple api for some ldap data. 

There are currently three available request types, which require header values to be set. The header attribute names are configurable.  

/auth: Requires at least a header representing the username, if password validation is desired, then a second header representing the password is needed. 

/hasrole: Requires two headers to be set, representing the username and the role to be verified as being assigned to the user

/roles: Requires only one header username, which will return a json formatted result with the username and a string array of roles. 

#Configuration File

The configuration file is yaml syntax. See the example file masconfig.yaml
There are hard coded defaults, some of which will render the application non-functional.

Detailed information located at <a href="masconfig.md">masconfig.md</a>

##Todo:

Soon on the list is to add customizable connection pooling.   

## Required Libraries:
gopkg.in/ldap.v2
gopkg.in/asn1-ber.v1
github.com/spf13/viper


## Contributing:

Bug reports and pull requests are welcome!


