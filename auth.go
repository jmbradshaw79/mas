package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/ldap.v2"
)

var cfg Config

//User struct definition for a user
type User struct {
	Username string
	Roles    []string
}

//Config Struct definition for configuration file marshalling
type Config struct {
	Listenport        string
	LDAPServer        string
	LDAPPort          int
	LDAPSearchBase    string
	LDAPSearchFilter  string
	LDAPBindUsername  string
	LDAPBindPassword  string
	UsernameHeader    string
	PasswordHeader    string
	RoleNameHeader    string
	VerifyPassword    bool
	RoleAttributeName string
	UsernameAttribute string
	UseTLS            bool
	TLSCert           string
	TLSKey            string
}

func main() {

	configViper()
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/roles", rolesHandler)
	http.HandleFunc("/hasrole", hasRoleHandler)
	if cfg.UseTLS {
		err := http.ListenAndServeTLS(":"+cfg.Listenport, cfg.TLSCert, cfg.TLSKey, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else {
		err := http.ListenAndServe(":"+cfg.Listenport, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}

//authHandler is the httpHandler that retrieves the username and password values from the http headers. Username header name defaults to "REMOTE_USER" and password header
//name defaults to "PASSWORD", these can be customized with the PasswordHeader and UsernameHeader attributes in the configuration file. The password header is optional,
//if VerifyPassword is set to false in the configuration file, only the lookup for the user will be performed (User if authentication is external e.g. client certificates)
//An http response of 200 will be return for a valid user and a 403 if invalid
func authHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get(cfg.UsernameHeader)
	password := r.Header.Get(cfg.PasswordHeader)
	if validUser(username, password) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

//rolesHandler wraps the getRoles function and returns a json encoded value for the username provided in the header. The header username name defaults to
//"REMOTE_USER" but can be customized in the configuration file with the UsernameHeader parameters
func rolesHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get(cfg.UsernameHeader)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getRoles(username))
}

//hasRoleHandler retrieves username and rolename header values. Header attribute names are in configuration file, default values are "REMOTE_USER" for username
//and "ROLE_NAME" for role name. This function wraps the hasRole function and returns a 200 if user has the role, and a 403 if user does not have role.
func hasRoleHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get(cfg.UsernameHeader)
	rolename := r.Header.Get(cfg.RoleNameHeader)
	if hasRole(username, rolename) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

//validUser returns a boolean value. Password validation is optional, if VerifyPassword is set to true, a bind will be attempted with provided username and password and true will
//be return if the user is found and the password is correct. If VerifyPassword is set to false, true will be returned if found in directory and false if not found.
func validUser(username string, password string) bool {
	sr, err := searchByUsername(username, cfg.LDAPSearchFilter, []string{"dn"})
	if err != nil {
		fmt.Printf("Error: %v", err)
		return false
	}
	if len(sr.Entries) != 1 {
		return false
	}
	if cfg.VerifyPassword {
		userdn := sr.Entries[0].DN
		l, _ := getConnection()
		defer l.Close()
		err = l.Bind(userdn, password)
		if err != nil {
			return false
		}
	}
	return true
}

//getRoles returns a User struct populated with roles which are based on attributes with that name defined as RoleAttributeName
//If exactly 1 entry for the given username is not found in the directory, or other errors occur. A User struct with an emply slice will be returned
func getRoles(username string) User {
	var r User
	r.Username = username
	sr, err := searchByUsername(username, cfg.LDAPSearchFilter, []string{"dn", cfg.RoleAttributeName})
	if err != nil {
		fmt.Printf("Error: %v", err)
		return r
	}

	//If expected result of 1 entry does not occur, return empty result
	if sr != nil && len(sr.Entries) != 1 {
		r.Roles = []string{}
		return r
	}

	entry := sr.Entries[0]

	for _, v := range entry.Attributes {
		if strings.EqualFold(v.Name, cfg.RoleAttributeName) {
			r.Roles = v.Values
		}
	}
	return r
}

//hasRole returns a boolean value. If the ldap entry found with the given username has an attribute with the name defined in RoleAttributeName and
//a value of role given, true will be returned, otherwise false will be returned.
func hasRole(username string, role string) bool {
	customfilter := "(&(" + cfg.RoleAttributeName + "=" + role + ")(" + cfg.UsernameAttribute + "=%s))"
	sr, err := searchByUsername(username, customfilter, []string{"dn"})
	if err != nil || len(sr.Entries) != 1 {
		return false
	}
	return true
}

//searchByUsername searches for an ldap entry based on the username string. A custom search filter can be provided which can use %s in place of
//where the username value should be placed. The attributes that will be return in the ldap.SearchResult result are defined in the attributes slice
func searchByUsername(username string, customsearchfilter string, attributes []string) (sr *ldap.SearchResult, errf error) {
	searchfilter := fmt.Sprintf(customsearchfilter, username)

	//Setting default searchfilter if none provided.
	if len(searchfilter) == 0 {
		searchfilter = fmt.Sprintf("("+cfg.UsernameAttribute+"=%s)", username)
	}
	l, err := getConnection()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	searchRequest := ldap.NewSearchRequest(
		cfg.LDAPSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchfilter,
		attributes,
		nil,
	)
	sr, errf = l.Search(searchRequest)
	return sr, errf
}

//getConnection returns an ldap connection.
func getConnection() (*ldap.Conn, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", cfg.LDAPServer, cfg.LDAPPort))
	if err != nil {
		fmt.Printf("Error: %v", err)
		return nil, err
	}
	err = l.Bind(cfg.LDAPBindUsername, cfg.LDAPBindPassword)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
	return l, err
}

func configViper() {
	viper.SetConfigName("masconfig")  // name of config file (without extension)
	viper.AddConfigPath("/etc/mas/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.mas") // call multiple times to add many search paths
	viper.AddConfigPath("./")         // optionally look for config in the working directory

	viper.SetEnvPrefix("MAS")
	viper.SetDefault("Listenport", 8080)
	viper.SetDefault("LDAPPort", 389)
	viper.SetDefault("PasswordHeader", "PASSWORD")
	viper.SetDefault("UsernameHeader", "REMOTE_USER")
	viper.SetDefault("UsernameAttribute", "uid")
	viper.SetDefault("RoleNameHeader", "ROLE_NAME")
	viper.SetDefault("RoleAttributeName", "memberOf")
	viper.SetDefault("LDAPServer", "localhost")
	viper.SetDefault("LDAPSearchBase", "dc=example,dc=net")
	viper.SetDefault("LDAPBindUsername", "cn=Directory Manager")
	viper.SetDefault("LDAPBindPassword", "changeit")
	viper.SetDefault("UseTLS", false)
	viper.SetDefault("TLSCert", "cert.pem")
	viper.SetDefault("TLSKey", "key.pem")

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %s", err))
	}

	cfg.Listenport = viper.GetString("Listenport")
	cfg.LDAPServer = viper.GetString("LDAPServer")
	cfg.LDAPPort = viper.GetInt("LDAPPort")
	cfg.LDAPSearchBase = viper.GetString("LDAPSearchBase")
	cfg.LDAPSearchFilter = viper.GetString("LDAPSearchFilter")
	cfg.LDAPBindUsername = viper.GetString("LDAPBindUsername")
	cfg.LDAPBindPassword = viper.GetString("LDAPBindPassword")
	cfg.UsernameHeader = viper.GetString("UsernameHeader")
	cfg.PasswordHeader = viper.GetString("PasswordHeader")
	cfg.RoleNameHeader = viper.GetString("RoleNameHeader")
	cfg.VerifyPassword = viper.GetBool("VerifyPassword")
	cfg.RoleAttributeName = viper.GetString("RoleAttributeName")
	cfg.UsernameAttribute = viper.GetString("UsernameAttribute")
	cfg.UseTLS = viper.GetBool("UseTLS")
	cfg.TLSCert = viper.GetString("TLSCert")
	cfg.TLSKey = viper.GetString("TLSKey")
}
