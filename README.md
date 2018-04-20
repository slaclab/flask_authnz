# flask_authnz
A small utility for authentication/authorization for flask based services

This utility supplies a couple of decorators that are used for PCDS authentication/authorization.

#### Basic Usage.
In your Flask context object create a DAL and a security object passing it the application name (in the example, _LogBook_)  
```
from flask_authnz import FlaskAuthnz, MongoDBRoles, UserGroups

security = FlaskAuthnz(MongoDBRoles(mongoclient, UserGroups()), "LogBook")
```

`UserGroups` uses `ldapsearch` to search LDAP for users, groups and groups memberships.
See the section below on LDAP for configuration and testing hints.

As the security object `MongoDBRoles` uses the MongoDB for roles, you'd need to pass in a MongoClient connected to a server that can read the "roles" collection in all the databases.
For example, the following snippet creates a user `roleReader` that can read the `roles` collection in all databases.
```
use admin
db.createRole(
 {
   role: "roleReader",
   privileges: [ {
     actions: [ "find" ],
     resource: { db: "", collection: "roles" }
   } ],
   roles: []
 }
)

db.createUser(
 {
   user: "roleReader",
   pwd: "...pwd...",
   roles: [ { role: "roleReader", db: "admin" } ]
 }
)
```


You can then mark your flask blueprint endpoints with decorators to indicate the need for authentication/authorization.
For example,
```
@logbook_service_blueprint.route("/processing_definitions/<experiment_name>", methods=["GET"])
@context.security.authentication_required
@context.security.authorization_required("read")
def processing_definitions(experiment_name):
```
- The order of the decorators is important.
- For experiment based authorization, it is important that the method takes in an argument called `experiment_name` that contains the experiment\_name.
- Authorization is based on privileges; so in this example, you are allowing those with the `read` privilege to get the `processing_definitions`
- The application will load and cache the privileges -> role mapping on startup.
- When an authorization request is made, we get a set of roles for the user and a set of roles that contain this privilege. The user is authorized if the intersection of these two sets is non-empty.


#### Configuring and testing LDAP
LDAP software typically have numerous configuration options; listing all of these is beyond the scope of this document.
Thankfully, OpenLDAP's `ldapsearch`, in recent versions of Linux, supports separation of the LDAP configuration from client applications.
In most Linuxes, OpenLDAP clients are configured using `/etc/openldap/ldap.conf`.
The most common configuration options are the `URI` and `BASE`.
In many cases, `TLS_REQCERT` is set to `never`.
LDAP configuration can be tested outside of the application using `ldapsearch`.
This module uses `ldapsearch -x` to determine users, groups and group memberships.
To use a command other than `ldapsearch -x`, set the environment variable, FLASK_AUTHNZ_LDAPSEARCH_COMMAND.
Test the various queries outside the app using LDAP queries like `ldapsearch -x "(uid=john*)" uid cn gecos`.

#### Running the tests.
To run the unittests, use `python -m unittests.runTests` from the root folder.
