#-*-coding: utf-8
"""
    flaskext.rbac
    ~~~~~~~~~~~~~

    Adds Role-based Access Control modules to application
"""

import itertools

from flask import request, abort

from .model import RoleMixin, UserMixin, anonymous


__all__ = ['RBAC', 'RoleMixin', 'UserMixin']


class AccessControlList(object):
    '''
    This class record rules for access controling.
    '''

    def __init__(self):
        self._allowed = []
        self._denied = []

    def allow(self, role, action, resource, with_children=True):
        '''Add allowing rules.'''
        if with_children:
            for r in role.get_children():
                permission = (r, action, resource)
                if not permission in self._allowed:
                    self._allowed.append(permission)
        permission = (role, action, resource)
        if not permission in self._allowed:
            self._allowed.append(permission)

    def deny(self, role, action, resource, with_children=True):
        '''Add denying rules.'''
        if with_children:
            for r in role.get_children():
                permission = (r, action, resource)
                if not permission in self._denied:
                    self._denied.append(permission)
        permission = (role, action, resource)
        if not permission in self._denied:
            self._denied.append(permission)

    def is_allowed(self, role, action, resource):
        '''Check whether role is allowed to access resource'''
        return (role, action, resource) in self._allowed

    def is_denied(self, role, action, resource):
        '''Check wherther role is denied to access resource'''
        return (role, action, resource) in self._denied


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

        self._role_model = kwargs.get('role_model', RoleMixin)
        self._user_model = kwargs.get('user_model', UserMixin)
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

        app.config.setdefault('RBAC_USE_WHITE', False)

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['rbac'] = _RBACState(self, app)

        self.acl.allow(anonymous, 'GET', app.view_functions['static'])

        if app.config['RBAC_USE_WHITE']:
            app.before_request(self._authenticate)

    def set_role_model(self, model):
        '''Set custom model of Role'''
        self._role_model = model

    def set_user_model(self, model):
        '''Set custom model of User'''
        self._user_model = model

    def set_user_loader(self, loader):
        '''Set user loader, which is used to load current user'''
        self._user_loader = loader

    def set_hook(self, hook):
        '''Set hook which call when permission is denied'''
        self.permission_failed_hook = hook

    def has_permission(self, method, endpoint, user=None):
        _user = user or self._user_loader()
        view_func = self.app.view_functions[endpoint]
        return self._check_permission(_user.roles, method, view_func)

    def check_perm(self, role, method, callback=None):
        def decorator(fview_func):
            if not self._check_permission([role], method, view_func):
                if callable(callback):
                    callback()
                else:
                    self._not_allow_hook()
            return view_func
        return decorator

    def user_loader(self, loader):
        self._user_loader = loader
        return loader

    def allow(self, roles, methods, with_children=True):
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.acl.allow(r, m, v, with_children)
            return view_func
        return decorator

    def deny(self, roles, methods, with_children=True):
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.acl.deny(r, m, v, with_children)
            return view_func
        return decorator

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

        if not hasattr(current_user, 'get_roles'):
            roles = [anonymous]
        else:
            roles = current_user.get_roles()

        permit = self._check_permission(roles, method, resource)
        if not permit:
            self._not_allow_hook()

    def _check_permission(self, roles, method, resource):
        _roles = set([anonymous])
        _methods = set(['*', method])
        _resources = set([None, resource])

        is_allowed = None
        _roles.update(roles)

        for r, m, res in itertools.product(_roles, _methods, _resources):
            permission = (r, m, res)
            if permission in self.acl._denied:
                return False

            if permission in self.acl._allowed:
                is_allowed = True

        return is_allowed

    def _not_allow_hook(self):
        if self.permission_failed_hook:
            return self.permission_failed_hook()
        else:
            abort(403)
