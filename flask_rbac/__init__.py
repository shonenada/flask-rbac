#-*- coding: utf-8 -*-
"""
    flaskext.rbac
    ~~~~~~~~~~~~~

    Adds Role-based Access Control module to application.

"""
import itertools

from flask import request, abort


class RBACRoleMixinModel(object):
    '''
    This mixin class provides implementations for the methods of Role model
    needed by Flask-RBAC.
    '''
    def get_name(self):
        '''Return the name of this role'''
        return self.name

    def get_parents(self):
        '''Iterate parents of this role'''
        for parent in self.parents:
            yield parent
            for grandparent in parent.get_parents():
                yield grandparent

    def get_family(self):
        '''Return family of this role'''
        yield self
        for parent in self.get_parents():
            yield parent

    @staticmethod
    def get_by_name(name):
        return everyone


class RBACUserMixinModel(object):
    '''
    This mixin class provides implementations for the methods of User model
    needed by Flask-RBAC.
    '''
    def get_roles(self):
        '''Return roles of this user'''
        for role in self.roles:
            role.get_family()


class EveryoneRole(RBACRoleMixinModel):

    def __init__(self):
        self.name = 'everyone'
        self.parents = []


everyone = EveryoneRole()


class PermissionDeny(Exception):
    def __init__(self, message="", **kwargs):
        super(PermissionDenied, self).__init__(message)
        self.kwargs = kwargs
        self.kwargs['message'] = message


class AccessControlList(object):
    '''
    This class record data for access controling.
    '''
    def __init__(self):
        self._allowed = []
        self._denied = []

    def allow(self, role, method, resource):
        '''Add a allowing rule.'''
        permission = (role, method, resource)
        if not permission in self._allowed:
            self._allowed.append(permission)

    def deny(self, role, method, resource):
        '''Add a denying rule.'''
        permission = (role, method, resource)
        if not permission in self._denied:
            self._denied.append(permission)

    def is_allowed(self, role, method, resource):
        return (role, method, resource) in self._allowed

    def is_denied(self, role, method, resource):
        return (role, method, resourced) in self._denied


class _RBACState(object):
    '''Records configuration for Flask-RBAC'''
    def __init__(self, rbac, app):
        self.rbac = rbac
        self.app = app


class RBAC(object):
    '''This class implements role-base access control module in flask.

    There are two way to initialize Flask-RBAC:

        app = Flask(__name__)
        rbac = RBAC(app)

    or

        rbac = RBAC
        def create_app():
            app = Flask(__name__)
            rbac.init_app(app)
            return app

    Difference between two ways see:
    https://github.com/mitsuhiko/flask-sqlalchemy/blob/master/flask_sqlalchemy/__init__.py#L592
    '''
    def __init__(self, app=None, **kwargs):
        self.acl = AccessControlList()
        self._role_model = kwargs.get('role_model', RBACRoleMixinModel)
        self._user_model = kwargs.get('user_model', RBACUserMixinModel)
        self._user_loader = kwargs.get('user_loader', None)
        self.permission_failed_hook = kwargs.get('permission_failed_hook')

        if app is not None:
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        '''
        Initialize application in Flask-RBAC.

        Adds (RBAC, app) to flask extensions.
        Adds hook to authenticate permission before request.
        '''
        self.app = app

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['rbac'] = _RBACState(self, app)

        self.acl.allow(
            everyone.get_name(), 'GET', app.view_functions['static'])

        app.before_request(self._authenticate)

    def set_role_model(self, model):
        '''Set custom model of Role.'''
        self._role_model = model

    def set_user_model(self, model):
        '''Set custom model of User.'''
        self._user_model = model

    def set_user_loader(self, loader):
        '''Set user loader, which is used to load current user'''
        self._user_loader = loader

    def set_hook(self, hook):
        self.permission_failed_hook = hook

    def _authenticate(self):
        '''Authenticate permission'''
        assert self.app, "Please initialize your application into Flask-RBAC."
        assert self._role_model, "Please set role model before authenticate."
        assert self._user_model, "Please set user model before authenticate."
        assert self._user_loader, "Please set user loader before authenticate."

        current_user = self._user_loader()
        assert (type(current_user) == self._user_model,
                "%s is not an instance of %s" %
                (current_user, self._user_model.__class__))

        endpoint = request.endpoint
        resource = self.app.view_functions.get(endpoint, None)

        if not resource:
            abort(404)

        method = request.method

        if not hasattr(current_user, 'roles'):
            roles = [everyone]
        else:
            roles = current_user.roles

        for role in roles:
            p = self._check_permission([role], method, resource)
            if not p:
                self._not_allow_hook()

    def _check_permission(self, roles, method, resource):

        _roles = set()
        _methods = set(["*", method])
        _resources = set([None, resource])
        is_allowed = None
        for role in roles:
            _roles.update(role.get_family())

        for r, m, res in itertools.product(_roles, _methods, _resources):
            permission = (r.get_name(), m, res)
            if permission in self.acl._denied:
                return False

            if permission in self.acl._allowed:
                is_allowed = True

        return is_allowed

    def has_permission(self, method, endpoint):
        current_user = self._user_loader()
        view_func = self.app.view_functions[endpoint]
        return self._check_permission(current_user.roles, method, view_func)

    def check_perm(self, role, method):
        def decorator(fview_func):
            if not self._check_permission([role], method, view_func):
                self._not_allow_hook()
            return view_func
        return decorator

    def resource_decorator(self):
        def decorator(view_func):
            self.acl.add_resource(view_func)
            return view_func
        return decorator

    def allow(self, roles, methods):
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.acl.allow(r, m, v)
            return view_func
        return decorator

    def deny(self, roles, methods):
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.acl.deny(r, m, v)
            return view_func
        return decorator

    def _not_allow_hook(self):
        if self.permission_failed_hook:
            return self.permission_failed_hook()
        else:
            abort(403)
