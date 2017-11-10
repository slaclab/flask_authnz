import unittest
import logging
import sys

from flask_authnz.mysql_dal import MySQLRoles 

logger = logging.getLogger(__name__)

'''
Test some aspects of the DAL DB.
Note this does not test the SQL queries themselves or the group membership functions. 
'''
    

class MockDBConnection(object):
    ''' Mocks a database connection. We simply look up the answer using function that determines the key.'''
    def __init__(self, queryresp, keyfn):
        self.queryresp = queryresp
        self.keyfn = keyfn
    def connect(self):
        return self
    def execute(self, statement, params):
        self.returnval = None # Do this right at the very first step...
        logger.debug("Executing statement %s with params %s", statement, params)
        self.returnval = self.queryresp.get(self.keyfn(statement, params), None)
        return self
    def fetchall(self):
        return self.returnval
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        pass        

class MockUserGroups(object):
    def __init__(self, user2groupsdict):
        self.user2groupsdict = user2groupsdict
    def get_user_posix_groups(self, user_id):
        return self.user2groupsdict.get(user_id, [])


class TestMySQLDal(unittest.TestCase):
    def test_group_has_editor(self):
        ''' Test if the user is assigned a role based on group membership''' 
        dbConn = MockDBConnection({
            MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP : [{'group_id': 'ps-editor'}, {'group_id': 'ps-sci'}]
            }, lambda statement, params : statement)
        mkgp = MockUserGroups({"PowerUser" : ['ps-editor', 'ps-readonly'], "ReadOnlyUser" : ['ps-readonly'] })
        dal = MySQLRoles(dbConn, mkgp)

        self.assertTrue(dal.has_slac_user_role(user_id="PowerUser", application_name="LogBook", user_role="Editor", experiment_id=100));
        self.assertFalse(dal.has_slac_user_role(user_id="ReadOnlyUser", application_name="LogBook", user_role="Editor", experiment_id=100));
        
        
        logger.debug("Test without experiment id")
        dbConn = MockDBConnection({
            MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP : [{'group_id': 'ps-editor'}, {'group_id': 'ps-sci'}]
            }, lambda statement, params : statement)
        dal = MySQLRoles(dbConn, mkgp)
        self.assertTrue(dal.has_slac_user_role(user_id="PowerUser", application_name="LogBook", user_role="Editor"));
        self.assertFalse(dal.has_slac_user_role(user_id="ReadOnlyUser", application_name="LogBook", user_role="Editor"));

    
    def test_user_has_editor(self):
        ''' Test if the user is assigned a role based on an entry with the userid''' 
        mkgp = MockUserGroups({"PowerUser" : ['ps-editor', 'ps-readonly'], "ReadOnlyUser" : ['ps-readonly'] })
        dbConn = MockDBConnection({
            (MySQLRoles.QUERY_SELECT_USER_WITH_ROLE_FOR_APP_EXP, 'PowerUser') : ['PowerUser'],
            (MySQLRoles.QUERY_SELECT_USER_WITH_ROLE_FOR_APP_EXP, 'ReadOnlyUser') : [],
            (MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP, '') : []
            }, lambda statement, params : (statement, params.get('user', '')))
        dal = MySQLRoles(dbConn, mkgp)
        self.assertTrue(dal.has_slac_user_role(user_id="PowerUser", application_name="LogBook", user_role="Editor", experiment_id=100));
        self.assertFalse(dal.has_slac_user_role(user_id="ReadOnlyUser", application_name="LogBook", user_role="Editor", experiment_id=100));

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestMySQLDal)
    unittest.TextTestRunner(verbosity=2).run(suite)