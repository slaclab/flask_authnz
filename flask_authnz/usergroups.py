import re
import os
import json
from collections import OrderedDict
import subprocess
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

ldapsearchCommand = os.environ.get("FLASK_AUTHNZ_LDAPSEARCH_COMMAND", "ldapsearch -x").split()

class UserGroups(object):
    def get_user_posix_groups(self, user_id):
        """
        Get the complete list of posix groups for the user.
        :param user_id: User id to get the posix groups for.
        :return: List of posix groups.
        """
        user_groups = [x["cn"] for x in ug.search_LDAP(ldapsearchCommand + ["(&(objectclass=posixGroup)(memberUid={0}))".format(user_id), "cn"])]
        logger.debug("User_id='%s' is member of groups %s." % (user_id, user_groups))
        return user_groups

    def get_group_members(self, group_name):
        """
        Get the members in a group
        :param group_name: Group name to get the members for.
        :return: List of member user id's
        """
        grpobj = ug.search_LDAP(ldapsearchCommand + ["(&(objectclass=posixGroup)(cn={0}))".format(group_name), "memberUid"])
        logger.debug("Group '%s' has members %s." % (group_name, grpobj))
        if grpobj:
            return grpobj[0]['memberUid']
        return []

    def get_groups_matching_pattern(self, group_pattern):
        """
        Get all the groups in the system matching a pattern.
        :param group_pattern: Pattern to match against
        :return: List of group names
        """
        groupnames = [x["cn"] for x in ug.search_LDAP(ldapsearchCommand + ["(&(objectclass=posixGroup)(cn={0}))".format(group_pattern), "cn"])]
        logger.debug("Group pattern '%s' has groups %s." % (group_pattern, groupnames))
        return groupnames

    def get_userids_matching_pattern(self, userid_pattern):
        """
        Get all the userids in the system matching a pattern.
        :param userid_pattern: Pattern to match against
        :return: List of dicts with the uid, cn and gecos
        """
        userobjs = ug.search_LDAP(ldapsearchCommand + ["(uid={0})".format(userid_pattern), "uid", "cn", "gecos"])
        logger.debug("Users matching pattern '%s' has entries %s." % (userid_pattern, userobjs))
        return userobjs

    def search_LDAP(self, query):
        try:
            logger.debug("Running LDAP query %s", query)
            response =  subprocess.run(query, check=False, stdout=subprocess.PIPE).stdout.decode("utf-8")
            return self.parseLDAPSearchResponse(response)
        except Exception as e:
            raise ValueError("Error while trying to run LDAP query: '%s'\n%s" % (query, e))


    def parseLDAPSearchResponse(self, response):
        """
        LDAPSearch responses are <name>: <value>, one per line with # as comment and blank lines to separate each object.
        This method parses such a response and returns an array of dicts.
        """
        retval = []
        current_obj = OrderedDict()
        comment_re = re.compile("^#.*$")
        blank_line_re = re.compile("^\s*$")
        n_v_line = re.compile("^(\w*):(.*)$")
        for line in response.split("\n"):
            if comment_re.match(line):
                continue
            elif blank_line_re.match(line):
                if current_obj and 'dn' in current_obj:
                    retval.append(current_obj)
                current_obj = OrderedDict()
            else:
                nvm = n_v_line.match(line)
                if nvm:
                    name = nvm.group(1)
                    value = nvm.group(2).strip()
                    if name in current_obj:
                        if isinstance(current_obj[name], list):
                            current_obj[name].append(value)
                        else:
                            current_obj[name] = [current_obj[name], value]
                    else:
                        current_obj[name] = value
                else:
                    logger.error("Not matching a line in LDAP response %s", line)
        if current_obj and 'dn' in current_obj:
            retval.append(current_obj)
        return retval

if __name__ == '__main__':
    ug = UserGroups()
    print(json.dumps([
        ug.get_user_posix_groups('mshankar'),
        ug.get_group_members('ps-data'),
        ug.get_groups_matching_pattern('ps-*'),
        ug.get_userids_matching_pattern('ms*')
        ]))
