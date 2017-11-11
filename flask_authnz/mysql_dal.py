import logging
from cachetools import TTLCache

__author__ = 'andrej.babic@cosylab.com'


logger = logging.getLogger(__name__)


class MySQLRoles(object):
    

    def __init__(self, db_connection, usergroupsgetter):
        """
        :param db_connection: Pass in the MultiMySQL connection to the roles database.
        :return:
        """
        self.db_connection = db_connection
        self.usergroupsgetter = usergroupsgetter
        self.exp_name_2_exp_id = TTLCache(maxsize=1000, ttl=600, missing=self.lookup_exp_id_for_exp_name_in_db)

    QUERY_SELECT_PRIVILEGES_AND_ROLES_FOR_APP = """
        SELECT 
            p.name as priv_name, r.name as role_name 
        FROM role r, priv p 
        WHERE p.role_id=r.id 
          AND r.app=%(application_name)s
        ORDER BY p.name, r.name;
        """

    def getPrivilegesForApplicationRoles(self, application_name):
        """
        Get the privileges for all the application roles for this application. 
        This is typically cached on startup and later used for authorization
        :param application_name
        :return a dict mapping privileges and the roles that contain that privilege.
        """
        # Return groups that have a specific role for a specific application.

        priv2roles = {}
        with self.db_connection.connect() as cursor:
            cursor.execute(self.QUERY_SELECT_PRIVILEGES_AND_ROLES_FOR_APP, {"application_name": application_name})
            for row in cursor.fetchall():
                priv_name = row['priv_name']
                role_name = row['role_name']
                if priv_name not in priv2roles:
                    priv2roles[priv_name] = set()
                priv2roles[priv_name].add(role_name)
        return priv2roles   

    QUERY_SELECT_EXP_ID_FOR_EXP_NAME = """
        SELECT 
            exp.id as experiment_id 
        FROM regdb.experiment exp 
        WHERE exp.name = %(experiment_name)s;
    """
    def lookup_exp_id_for_exp_name_in_db(self, experiment_name):
        """
        Determine the experiment id for an experiment from the database.
        :param experiment_name - The name of the experiment - for example, diadaq13
        :return: - The experiment id; if there is no experiment with this name, return None
        """
        with self.db_connection.connect() as cursor:
            cursor.execute(self.QUERY_SELECT_EXP_ID_FOR_EXP_NAME, {"experiment_name": experiment_name})
            return cursor.fetchone()

    def get_experiment_id_for_name(self, experiment_name):
        """
        Get the experiment id for the given experiment name
        :param experiment_name - The name of the experiment - for example, diadaq13
        :return: - The experiment id; if there is no experiment with this name, return None
        """
        return exp_name_2_exp_id.get(experiment_name, None)
    
    def has_slac_user_role(self, user_id, application_name, user_role, experiment_id=None):
        """
        Check if SLAC user has the appropriate role in the application.
        :param user_id: User id to verify.
        :param application_name: Application name.
        :param user_role: Role of the user.
        :param experiment_id: Not mandatory.
        :return:
        """
        # Check if the user is directly mentioned in the database.
        if self.__has_user_role_in_db(user_id, application_name, user_role, experiment_id):
            logger.debug("User_id='%s' has role '%s' in application '%s' for experiment '%s'."
                          % (user_id,
                             user_role,
                             application_name,
                             experiment_id))
            return True
        
        authorized_groups = [group["group_id"] for group in
                             self.__get_groups_for_role_in_application_from_db(application_name,
                                                                                 user_role,
                                                                                 experiment_id)]
        # There are no role groups for this application.
        if not authorized_groups:
            logger.debug("User_id='%s' is not authorized for role '%s' on application '%s'. "
                          "No authorized groups for this role either." % (user_id, user_role,
                                                                          application_name))
            return False
        
        logger.debug("These groups '%s' are authorized for role '%s' in application '%s' for experiment '%s'."
                      % (authorized_groups,
                         user_role,
                         application_name,
                         experiment_id))

        try:
            user_groups = self.usergroupsgetter.get_user_posix_groups(user_id)
        except ValueError as e:
            logger.exception("Exception when trying to determine groups for user %s" % (user_id))
            return False

        logger.debug("User '%s' belongs to these groups '%s'"
                      % (user_id,
                         user_groups))

        # Check if the user is in any posix group specified on the application.
        return bool(set(user_groups) & set(authorized_groups))
    
    QUERY_SELECT_USER_WITH_ROLE_FOR_APP_EXP = """
        SELECT
            users.user as user
        FROM
            user users
        INNER JOIN
            role roles ON users.role_id = roles.id
            AND roles.app = %(app)s
            AND roles.name = %(role)s
        WHERE
            users.user = %(user)s
            AND (users.exp_id = %(experiment_id)s OR users.exp_id IS NULL) 
        """

    QUERY_SELECT_USER_WITH_ROLE_FOR_APP = """
            SELECT
                users.user as user
            FROM
                user users
            INNER JOIN
                role roles ON users.role_id = roles.id
                AND roles.app = %(app)s
                AND roles.name = %(role)s
            WHERE
                users.user = %(user)s
            """
    QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP = """
            SELECT
                DISTINCT SUBSTRING(users.user, 5) as group_id
            FROM
                user users
            INNER JOIN
                role roles ON users.role_id = roles.id
                AND roles.name = %(role)s
                AND roles.app = %(app)s
            WHERE
                users.user like 'gid:%%'
                AND (users.exp_id = %(experiment_id)s OR users.exp_id IS NULL) 
            ORDER BY users.user;
            """
    
    QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP = """
            SELECT
                DISTINCT SUBSTRING(users.user, 5) as group_id
            FROM
                user users
            INNER JOIN
                role roles ON users.role_id = roles.id
                AND roles.name = %(role)s
                AND roles.app = %(app)s
            WHERE
                users.user like 'gid:%%'
            ORDER BY users.user;
            """
        
    def __has_user_role_in_db(self, user_id, app_name, user_role, experiment_id):
        """
        Check if user has an explicitly defined role on the specified application.
        :param user_id: User to check.
        :param user_role: Role to verify.
        :param app_name: Application name.
        :param experiment_id: The id (primary key) of the experiment we want to check this permission for.
        :return: True if the user has the role, False otherwise.
        """
        if experiment_id:
            # Return rows if the specified user has the specified role in the specified app.
            with self.db_connection.connect() as cursor:
                cursor.execute(self.QUERY_SELECT_USER_WITH_ROLE_FOR_APP_EXP, {"user": user_id,
                                                                     "role": user_role,
                                                                     "app": app_name, 
                                                                     "experiment_id" : experiment_id})
                val = cursor.fetchall()
                return bool(val)
        else:
            # Return rows if the specified user has the specified role in the specified app.
            with self.db_connection.connect() as cursor:
                cursor.execute(self.QUERY_SELECT_USER_WITH_ROLE_FOR_APP, {"user": user_id,
                                                                     "role": user_role,
                                                                     "app": app_name})
                val = cursor.fetchall()
                return bool(val)

    def __get_groups_for_role_in_application_from_db(self, app_name, user_role, experiment_id):
        """
        Return the set of groups that has a specific role in the application.
        :param user_role: The role to look for.
        :param app_name: Application name.
        :param experiment_id: The id (primary key) of the experiment we want to check this permission for.
        :return: List of groups with specified role on specified application.
        """
        if experiment_id:
            # Return groups that have a specific role for a specific application.
            with self.db_connection.connect() as cursor:
                cursor.execute(self.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP_EXP, {"role": user_role,
                                                                       "app": app_name,
                                                                       "experiment_id" : experiment_id})
                return cursor.fetchall()
        else:
            # Return groups that have a specific role for a specific application.
            with self.db_connection.connect() as cursor:
                cursor.execute(self.QUERY_SELECT_GROUPS_WITH_ROLE_FOR_APP, {"role": user_role,
                                                                       "app": app_name})
                return cursor.fetchall()
    
