import unittest
import logging
import sys
import flask

from flask_authnz.mongodb_dal import MongoDBRoles 
from flask_authnz.flask_authnz import FlaskAuthnz 

from werkzeug.exceptions import HTTPException

app = flask.Flask(__name__)

logger = logging.getLogger(__name__)


# Print and retun true
def part(msg, **kwargs):
    def f():
        print(msg)
        return True
    return f

class MockUserGroups(object):
    def __init__(self, user2groupsdict):
        self.user2groupsdict = user2groupsdict
    def get_user_posix_groups(self, user_id):
        return self.user2groupsdict.get(user_id, [])
    
class MockDatabase(object):
    def __init__(self, roledata):
        self.roledata = roledata
    def find(self, params_dict):
        ret = []
        logger.debug("Looking for dict params %s", params_dict)
        for role in self.roledata:
            if all(role[key] == params_dict[key] for key in params_dict.keys()):
                ret.append(role)
        logger.debug("Returning %s for dict params %s", ret, params_dict)
        return ret


class TestFlaskAuthz(unittest.TestCase):
    """
    We have two roles; an Editor role and a Reader role.
    We have these users - PowerUser, PI and ReadOnlyUser and various experiment specific and global users
    """
    def test_group_has_editor(self):
        mgClient = {
            "roles": {
                "roles": MockDatabase( [ 
                    { 
                        "app" : "LogBook", 
                        "name" : "Editor", 
                        "privileges" : [ "read", "post", "manage_shifts", "edit", "delete" ], 
                        "players" : [ "uid:specific_global_editor", "ps_global_editors" ] },
                    {
                        "app" : "LogBook", 
                        "name" : "Reader", 
                        "privileges" : [ "read"], 
                        "players" : [ "uid:specific_global_reader", "ps_global_readers" ] 
                    }
                    ] )
                },
             "xpp123456": {
                "roles": MockDatabase( [ 
                    { 
                        "app" : "LogBook", 
                        "name" : "Editor", 
                        "players" : [ "uid:specific_xpp123456_editor", "ps_xpp123456_editors" ] },
                    {
                        "app" : "LogBook", 
                        "name" : "Reader", 
                        "players" : [ "uid:specific_xpp123456_reader", "ps_xpp123456_readers" ] 
                    }
                    ] )
                },
             "mec987654": {
                "roles": MockDatabase( [ 
                    { 
                        "app" : "LogBook", 
                        "name" : "Editor", 
                        "players" : [ "uid:specific_mec987654_editor", "ps_mec987654_editors" ] },
                    {
                        "app" : "LogBook", 
                        "name" : "Reader", 
                        "players" : [ "uid:specific_mec987654_reader", "ps_mec987654_readers" ] 
                    }
                    ] )
                }
            }
        mkgp = MockUserGroups( {
            "PowerUser" : ['ps_global_editors', 'ps_global_readers'], 
            "ReadOnlyUser" : ['ps_global_readers'],
            "xpp123456_PI" : ["ps_xpp123456_editors"],
            "xpp123456_readonly" : ["ps_xpp123456_readers"]             
            } )
        dal = MongoDBRoles(mgClient, mkgp)
        security = FlaskAuthnz(dal, "LogBook")

        app = flask.Flask(__name__)
        app.secret_key = "This is a secret key that is somewhat temporary."
        with app.test_request_context('/'):
            with self.assertRaises(HTTPException) as http_error:
                self.assertRaises(Exception, security.authentication_required(part("Should not have authenticated...."))())
                self.assertEqual(http_error.exception.code, 403)            
            
            flask.request.environ["HTTP_REMOTE_USER"] = "ReadOnlyUser"
            self.assertTrue(security.authentication_required(part("Authenticated...."))())
            self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'xpp123456'}))
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("edit")(part)("Authorized", **{'experiment_name':'xpp123456'}))
                self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'xpp123456'}))
                self.assertEqual(http_error.exception.code, 403)            

            flask.request.environ["HTTP_REMOTE_USER"] = "specific_xpp123456_reader"
            self.assertTrue(security.authentication_required(part("Authenticated...."))())
            self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'xpp123456'}))
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("edit")(part)("Authorized", **{'experiment_name':'xpp123456'}))
                self.assertEqual(http_error.exception.code, 403)            
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'mec987654'}))
                self.assertEqual(http_error.exception.code, 403)            
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("edit")(part)("Authorized", **{'experiment_name':'mec987654'}))
                self.assertEqual(http_error.exception.code, 403)            

            flask.request.environ["HTTP_REMOTE_USER"] = "xpp123456_PI"
            self.assertTrue(security.authentication_required(part("Authenticated...."))())
            self.assertTrue(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'xpp123456'}))
            self.assertTrue(security.authorization_required("edit")(part)("Authorized", **{'experiment_name':'xpp123456'}))
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("read")(part)("Authorized", **{'experiment_name':'mec987654'}))
                self.assertEqual(http_error.exception.code, 403)            
            with self.assertRaises(HTTPException) as http_error:
                self.assertFalse(security.authorization_required("edit")(part)("Authorized", **{'experiment_name':'mec987654'}))
                self.assertEqual(http_error.exception.code, 403)            
