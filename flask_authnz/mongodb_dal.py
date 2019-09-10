import logging
from cachetools import TTLCache

logger = logging.getLogger(__name__)


class MongoDBRoles(object):
    """
    Authorization using MongoDB.
    Roles in MongoDB are distributed across databases.
    The "roles" database has the application roles to privileges mappings in addition to the "global" all-experiment players.
    All of these are stored in the "roles" collection.
    Experiment specific roles are in a "roles" collection for the experiment specific database.
    Thus, authz requires a user that can read the "roles" collection in all databases.
    """


    def __init__(self, mongoclient, usergroupsgetter):
        """
        :param mongoclient: The PyMongo client to use.
        :return:
        """
        self.mongoclient = mongoclient
        self.usergroupsgetter = usergroupsgetter

    def getPrivilegesForApplicationRoles(self, application_name):
        """
        Get the privileges for all the application roles for this application.
        This is typically cached on startup and later used for authorization
        :param application_name
        :return a dict mapping privileges and the roles that contain that privilege.
        """
        # Privileges are stored in the roles database
        priv2roles = {}
        for role in self.mongoclient["site"]["roles"].find({"app": application_name}):
            role_name = role["name"]
            privileges = role.get("privileges", [])
            for privilege in privileges:
                if privilege not in priv2roles:
                    priv2roles[privilege] = set()
                priv2roles[privilege].add(role_name)
        return priv2roles

    def has_slac_user_role(self, user_id, application_name, role_name, experiment_name=None, instrument=None):
        """
        Check if SLAC user has the appropriate role in the application.
        :param user_id: User id to verify.
        :param application_name: Application name.
        :param role_name: Role name
        :param experiment_name: This is optional; in which case only the global roles apply.
        :param instrument: The instrument for this experiment; can be used for instrument level roles.
        :return:
        """
        role_players = set()
        for role in self.mongoclient["site"]["roles"].find({"app": application_name, "name": role_name}):
            for player in role.get("players", []):
                role_players.add(player)
        if experiment_name:
            for role in self.mongoclient[experiment_name]["roles"].find({"app": application_name, "name": role_name}):
                for player in role.get("players", []):
                    role_players.add(player)
        if instrument:
            instr_obj = self.mongoclient["site"]["instruments"].find_one({"_id": instrument})
            if instr_obj:
                for in_role in instr_obj.get("roles", []):
                    if in_role.get("app", None) == application_name and in_role.get("name", None) == role_name:
                        for player in in_role.get("players", []):
                            role_players.add(player)


        # Check if the user is directly mentioned in the database.
        if "uid:"+user_id in role_players:
            logger.info("User_id='%s' directly has role '%s' in application '%s' for experiment '%s'."
                          % (user_id,
                             role_name,
                             application_name,
                             experiment_name))
            return True


        authorized_groups = [x for x in role_players if not x.startswith("uid:")]


        # There are no role groups for this application.
        if not authorized_groups:
            logger.debug("User_id='%s' is not authorized for role '%s' on application '%s'. "
                          "No authorized groups for this role either." % (user_id, role_name,
                                                                          application_name))
            return False

        logger.debug("These groups '%s' are authorized for role '%s' in application '%s' for experiment '%s'."
                      % (authorized_groups,
                         role_name,
                         application_name,
                         experiment_name))

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
