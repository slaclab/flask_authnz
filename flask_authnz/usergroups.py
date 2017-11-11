import subprocess
import logging
logger = logging.getLogger(__name__)

class UserGroups(object):
    def get_user_posix_groups(self, user_id):
        """
        Get the complete list of posix groups for the user.
        :param user_id: User id to get the posix groups for.
        :return: List of posix groups.
        """
        try:
            user_groups = subprocess.check_output(['id', '-Gn', user_id]).decode("utf-8").strip().split(' ')
            logger.debug("User_id='%s' is member of groups %s." % (user_id, user_groups))
            return user_groups
        except subprocess.CalledProcessError as e:
            user_groups = e.output.strip().split(' ')
            return user_groups
        except Exception as e:
            raise ValueError("Error while trying to read the unix groups for user_id:'%s'. "
                             "Does this user exists?\n%s" % (user_id, e))

