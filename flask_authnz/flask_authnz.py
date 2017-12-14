import logging
from functools import wraps

from flask import request, jsonify, url_for, abort, session
from werkzeug.utils import redirect

__author__ = 'andrej.babic@cosylab.com'

logger = logging.getLogger(__name__)

class FlaskAuthnz(object):
    """
    General security client for flask web services at PSDM/SLAC. 
    We assume that the application is behind a web service tied into SLAC SSO (WebAuth/SAML).
    During initialization, pass in some form of a database object that provides for introspecting the roles.
    Our privilege model has these variants 
    --> Roles are collections of application privileges. We load application privileges on startup.
    --> Users or groups are assigned roles.
    --> Users/groups are assigned roles in the context of experiments/instruments.
    """

    def __init__(self, roles_dal, application_name, redirect_url=None):
        """
        Initialize the security client.
        :param roles_dal: A data access object to get to the roles/privileges.
        :param application_name: The name of this application.
        :param redirect_url: Redirect to this URL if we fail authentication. Note that with WebAuth integration, you will not be needing this. 
        """
        self.roles_dal = roles_dal
        self.application_name = application_name
        self.redirect_url = redirect_url
        self.priv2roles = roles_dal.getPrivilegesForApplicationRoles(application_name)
        self.session_roles_name = "APPLICATION_ROLES_" + self.application_name

    
    def authentication_required(self, wrapped_function):
        """
        Primary decorator to mandate that an authentication is required for this method.
        """
        @wraps(wrapped_function)
        def function_interceptor(*args, **kwargs):
	    # The user is authenticated.
            if self.is_user_authenticated():
                return wrapped_function(*args, **kwargs)
            else:
                if self.redirect_url:
                    return redirect(url_for(self.redirect_url, next=request.url))
                else:
                    logger.info("User is not logged in; sending a 403 response")
                    abort(403)
                    return None 

        return function_interceptor

    def authorization_required(self, *params):
        '''
        Decorator for experiment specific authorization - decorate your function in this order
        _at_logbook_service_blueprint.route("/get_batch_executables/<experiment_name>", methods=["GET"])
        _at_context.security.authentication_required
        _at_context.security.authorization_required("read")
        To pass in an experiment_name, use the variable name experiment_name in your flask variable names
        Note you are passing in privileges as part of the authorization_required decorator; not the roles.  
        '''
        if len(params) < 1:
            raise Exception("Application privilege not specified when specifying the authorization")
        priv_name = params[0]
        if priv_name not in self.priv2roles:
            raise Exception("Please specify an appropriate application privilege for the authorization_required decorator " + ",".join(self.priv2roles.keys()))
        def wrapper(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                experiment_name = kwargs.get('experiment_name', None)
                logger.info("Looking to authorize %s for app %s for privilege %s for experiment %s" % (self.get_current_user_id(), self.application_name, priv_name, experiment_name))
                if not self.check_privilege_for_experiment(priv_name, experiment_name):
                    abort(403)
                return f(*args, **kwargs)
            return wrapped
        return wrapper 

    def get_current_user_id(self):
        """
        Get the user id from the proxy.
        :return: User id in the proxy header.
        """
        return request.environ.get("HTTP_REMOTE_USER", None)

    def is_user_authenticated(self):
        """
        Check if user is authenticated.
        :return: True if user is authenticated.
        """
        if self.get_current_user_id():
            return True
        return False

    def check_privilege_for_experiment(self, priv_name, experiment_name):
        """
        Check to see if this use has the necessary privilege for this experiment.
        The application caches all the privilege -> role mappings on startup. 
        We check to see if this user has any of the roles necessary for the privilege.
        """
        for role_name in self.priv2roles[priv_name]:
            if self.__authorize_slac_user_for_experiment(role_name, experiment_name):
                logger.debug("Role %s grants privilege %s for user %s for experiment %s" % (role_name, priv_name, self.get_current_user_id(), experiment_name))
                return True
        logger.warn("Did not find any role with privilege %s for user %s for experiment %s" % (priv_name, self.get_current_user_id(), experiment_name))
        return False

            
    def __authorize_slac_user_for_experiment(self, application_role, experiment_name=None):
        """
        Check if SLAC user has the appropriate role in self.application.
        :param application_role: Application role in self.application needed to perform this task
        :param experiment_name: Optional; is this request within the context of an experiment.
        If so, this is the primary key in the regdb database to the experiment.
        :return:
        """
        user_id = self.get_current_user_id()
        role_fq_name = self.application_name + "/" + application_role
        session_app_roles = session.get(self.session_roles_name, {})
        if role_fq_name in session_app_roles:
            logger.info("Found fq_name %s in session for user %s" % (role_fq_name, user_id))
            if experiment_name:
                if experiment_name in session_app_roles[role_fq_name]:
                    logger.info("Found experiment %s for application role %s in session for user %s" % (experiment_name, role_fq_name, user_id))
                    return True
            else:
                # Caller did not specify experiment; so presence of the fq_name is enough for authorization.
                logger.info("Caller did not specify experiment but we found fq_name %s in session for user %s" % (role_fq_name, user_id))
                return True                    
        
        if self.roles_dal.has_slac_user_role(user_id,
                                                 self.application_name,
                                                 application_role,
                                                 experiment_name):
            # Add an entry in the session.
            logger.info("Found application role %s for experiment %s in db for user %s" % (role_fq_name, experiment_name, user_id))
            if role_fq_name not in session_app_roles:
                session_app_roles[role_fq_name] = []
            if experiment_name and experiment_name not in session_app_roles[role_fq_name]:
                session_app_roles[role_fq_name].append(experiment_name)
            session[self.session_roles_name] = session_app_roles
            return True
        else:
            logger.info("Did not find application role %s for experiment %s in db for user %s" % (role_fq_name, experiment_name, user_id))
            return False
            
        return False

