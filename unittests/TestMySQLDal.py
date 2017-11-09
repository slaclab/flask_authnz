import unittest
from unittest.mock import patch
import logging
import sys
sys.path.append('..')


from flask_authnz.mysql_dal import MySQLRoles 

logger = logging.getLogger(__name__)
    

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

class TestMySQLDal(unittest.TestCase):
    def test_group_has_editor(self):
        dbConn = MockDBConnection({
            MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP : [{'group_id': 'ps-editor'}, {'group_id': 'ps-sci'}]
            }, lambda statement, params : statement)
        dal = MySQLRoles(dbConn)
        with patch.object(dal, 'get_user_posix_groups') as mocked_method:
            mocked_method.return_value=['ps-editor', 'ps-readonly']
            self.assertTrue(dal.has_slac_user_role(user_id="PowerUser", application_name="LogBook", user_role="Editor", experiment_id=100));
        with patch.object(dal, 'get_user_posix_groups') as mocked_method:
            mocked_method.return_value=['ps-readonly']
            self.assertFalse(dal.has_slac_user_role(user_id="ReadOnlyUser", application_name="LogBook", user_role="Editor", experiment_id=100));
        logger.debug("Test without experiment id")
        dbConn = MockDBConnection({
            MySQLRoles.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP : [{'group_id': 'ps-editor'}, {'group_id': 'ps-sci'}]
            }, lambda statement, params : statement)
        dal = MySQLRoles(dbConn)
        with patch.object(dal, 'get_user_posix_groups') as mocked_method:
            mocked_method.return_value=['ps-editor', 'ps-readonly']
            self.assertTrue(dal.has_slac_user_role(user_id="PowerUser", application_name="LogBook", user_role="Editor"));
        with patch.object(dal, 'get_user_posix_groups') as mocked_method:
            mocked_method.return_value=['ps-readonly']
            self.assertFalse(dal.has_slac_user_role(user_id="ReadOnlyUser", application_name="LogBook", user_role="Editor"));
    
if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestMySQLDal)
    unittest.TextTestRunner(verbosity=2).run(suite)