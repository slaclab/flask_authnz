import unittest
import logging
import sys
import flask

from flask_authnz.mysql_dal import MySQLRoles 
from flask_authnz.flask_authnz import FlaskAuthnz 

from .TestMySQLDal import MockDBConnection, MockUserGroups

from werkzeug.exceptions import HTTPException

app = flask.Flask(__name__)

# Print and retun true
def part(msg, **kwargs):
    def f():
        print(msg)
        return True
    return f

class TestFlaskAuthz(unittest.TestCase):
    def test_group_has_editor(self):
        dbConn = MockDBConnection({
            (MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP, 'Editor') : [{'group_id': 'ps-editor'}],
            (MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP, 'Reader') : [{'group_id': 'ps-readonly'}],
            (MySQLRoles.QUERY_SELECT_PRIVILEGES_AND_ROLES_FOR_APP, '') : [{'priv_name': 'read', 'role_name': 'Editor'}, {'priv_name': 'write', 'role_name': 'Editor'}, {'priv_name': 'read', 'role_name': 'Reader'}]
            }, lambda statement, params : (statement, params.get('role', '')))
        mkgp = MockUserGroups({"PowerUser" : ['ps-editor', 'ps-readonly'], "ReadOnlyUser" : ['ps-readonly'] })
        dal = MySQLRoles(dbConn, mkgp)
        security = FlaskAuthnz(dal, "LogBook")

        app = flask.Flask(__name__)
        app.secret_key = "This is a secret key that is somewhat temporary."
        with app.test_request_context('/'):
            with self.assertRaises(HTTPException) as http_error:
                self.assertRaises(Exception, security.authentication_required(part("Should not have authenticated...."))())
                self.assertEqual(http_error.exception.code, 403)            
            
            flask.request.environ["HTTP_REMOTE_USER"] = "ReadOnlyUser"
            self.assertTrue(security.authentication_required(part("Authenticated...."))())
            self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_id':100}))
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("write")(part)("Authorized", **{'experiment_id':100}))
                self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_id':100}))
                self.assertEqual(http_error.exception.code, 403)            

