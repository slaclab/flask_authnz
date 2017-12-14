# flask_authnz
A small utility for authentication/authorization for flask based services

This utility supplies a couple of decorators that are used for PCDS authentication/authorization.

#### Basic Usage.
In your Flask context object create a DAL and a security object passing it the application name (in the example, _LogBook_)  
```
from flask_authnz import FlaskAuthnz, MongoDBRoles, UserGroups

security = FlaskAuthnz(MongoDBRoles(mongoclient, UserGroups()), "LogBook")
```

As this uses the MongoDB for roles, you'd need to pass in a MongoClient connected to a server that can read the "roles" collection in all the databases.

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

#### Running the tests.
To run the unittests, use `python -m unittests.runTests` from the root folder.

