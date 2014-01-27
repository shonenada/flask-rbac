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
        self.seted = False

    def allow(self, role, method, resource, with_children=True):
        '''Add allowing rules.'''
        if with_children:
            for r in role.get_children():
                permission = (r.get_name(), method, resource)
                if not permission in self._allowed:
                    self._allowed.append(permission)
        permission = (role.get_name(), method, resource)
        if not permission in self._allowed:
            self._allowed.append(permission)

    def deny(self, role, method, resource, with_children=True):
        '''Add denying rules.'''
        if with_children:
            for r in role.get_children():
                permission = (r.get_name(), method, resource)
                if not permission in self._denied:
                    self._denied.append(permission)
        permission = (role.get_name(), method, resource)
        if not permission in self._denied:
            self._denied.append(permission)

    def is_allowed(self, role, method, resource):
        '''Check whether role is allowed to access resource'''
        return (role, method, resource) in self._allowed

    def is_denied(self, role, method, resource):
        '''Check wherther role is denied to access resource'''
        return (role, method, resource) in self._denied


class _RBACState(object):
    '''Records configuration for Flask-RBAC'''
    def __init__(self, rbac, app):
        self.rbac = rbac
        self.app = app


class RBAC(object):
    """This class implements role-based access control module in Flask.
    There are two way to initialize Flask-RBAC::

        app = Flask(__name__)
        rbac = RBAC(app)

    or::

        rbac = RBAC
        def create_app():
            app = Flask(__name__)
            rbac.init_app(app)
            return app

    :param app: the Flask object
    :param role_model: custom role model
    :param user_model: custom user model
    :param user_loader: custom user loader, used to load current user
    :param permission_failed_hook: called when permission denied.
    """

    def __init__(self, app=None, **kwargs):
        """Initialize with app."""
        self.acl = AccessControlList()
        self.before_acl = {'allow': [], 'deny': []}

        self._role_model = kwargs.get('role_model', RoleMixin)
        self._user_model = kwargs.get('user_model', UserMixin)
        self._user_loader = kwargs.get('user_loader', None)
        self.permission_failed_hook = kwargs.get('permission_failed_hook')

        if app is not None:
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        """Initialize application in Flask-RBAC.
        Adds (RBAC, app) to flask extensions.
        Adds hook to authenticate permission before request.

        :param app: Flask object
        """
        self.app = app

        app.config.setdefault('RBAC_USE_WHITE', False)

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['rbac'] = _RBACState(self, app)

        self.acl.allow(anonymous, 'GET', app.view_functions['static'])
        app.before_first_request(self._setup_acl)

        app.before_request(self._authenticate)

    def set_role_model(self, model):
        """Set custom model of role.

        :param model: Model of role.
        """
        self._role_model = model

    def set_user_model(self, model):
        """Set custom model of User

        :param model: Model of user
        """
        self._user_model = model

    def set_user_loader(self, loader):
        """Set user loader, which is used to load current user.
        An example::

            from flask.ext.login import current_user
            rbac.set_user_loader(lambda: current_user)

        :param loader: Current user function.
        """
        self._user_loader = loader

    def set_hook(self, hook):
        """Set hook which called when permission is denied
        If you haven't set any hook, Flask-RBAC will call::

            abort(403)

        :param hook: Hook function
        """
        self.permission_failed_hook = hook

    def has_permission(self, method, endpoint, user=None):
        """Return does the current user can access the resource.
        Example::

            @app.route('/some_url', methods=['GET', 'POST'])
            @rbac.allow(['anonymous'], ['GET'])
            def a_view_func():
                return Response('Blah Blah...')

        If you are not logged.

        `rbac.has_permission('GET', 'a_view_func')` return True.
        `rbac.has_permission('POST', 'a_view_func')` return False.

        :param method: The method wait to check.
        :param endpoint: The application endpoint.
        :param user: user who you need to check. Current user by default.
        """
        _user = user or self._user_loader()
        roles = _user.get_roles()
        view_func = self.app.view_functions[endpoint]
        return self._check_permission(roles, method, view_func)

    def check_perm(self, role, method, callback=None):
        def decorator(view_func):
            if not self._check_permission([role], method, view_func):
                if callable(callback):
                    callback()
                else:
                    self._deny_hook()
            return view_func
        return decorator

    def user_loader(self, loader):
        self._user_loader = loader
        return loader

    def allow(self, roles, methods, with_children=True):
        """This is a decorator function.

        You can allow roles to access the view func with it.

        An example::

            @app.route('/website/setting', methods=['GET', 'POST'])
            @rbac.allow(['administrator', 'super_user'], ['GET', 'POST'])
            def website_setting():
                return Response('Setting page.')

        :param roles: List, each name of roles. Please note that,
                      `anonymous` is refered to anonymous.
                      If you add `anonymous` to the rule,
                      everyone can access the resource,
                      unless you deny other roles.
        :param methods: List, each name of methods.
                        methods is valid in ['GET', 'POST', 'PUT', 'DELETE']
        :param with_children: Whether allow children of roles as well.
                              True by default.
        """
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.before_acl['allow'].append((r, m, v, with_children))
            return view_func
        return decorator

    def deny(self, roles, methods, with_children=True):
        """This is a decorator function.

        You can deny roles to access the view func with it.

        An example::

            @app.route('/article/post', methods=['GET', 'POST'])
            @rbac.deny(['anonymous', 'unactivated_role'], ['GET', 'POST'])
            def article_post():
                return Response('post page.')

        :param roles: List, each name of roles.
        :param methods: List, each name of methods.
                        methods is valid in ['GET', 'POST', 'PUT', 'DELETE']
        :param with_children: Whether allow children of roles as well.
                              True by default.
        """
        def decorator(view_func):
            _methods = [m.upper() for m in methods]
            for r, m, v in itertools.product(roles, _methods, [view_func]):
                self.before_acl['deny'].append((r, m, v, with_children))
            return view_func
        return decorator

    def _authenticate(self):
        assert self.app, "Please initialize your application into Flask-RBAC."
        assert self._role_model, "Please set role model before authenticate."
        assert self._user_model, "Please set user model before authenticate."
        assert self._user_loader, "Please set user loader before authenticate."

        use_white = self.app.config['RBAC_USE_WHITE']

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

        if use_white:
            permit = (self._check_permission(roles, method, resource) == True)
        else:
            permit = (self._check_permission(roles, method, resource) != False)

        if not permit:
            return self._deny_hook()

    def _check_permission(self, roles, method, resource):
        if not self.acl.seted:
            self._setup_acl()

        _roles = set([anonymous])
        _methods = set(['*', method])
        _resources = set([None, resource])

        is_allowed = None
        _roles.update(roles)

        for r, m, res in itertools.product(_roles, _methods, _resources):
            permission = (r.get_name(), m, res)
            if permission in self.acl._denied:
                return False

            if permission in self.acl._allowed:
                is_allowed = True
        return is_allowed

    def _deny_hook(self):
        if self.permission_failed_hook:
            return self.permission_failed_hook()
        else:
            abort(403)

    def _setup_acl(self):
        for rn, method, resource, with_children in self.before_acl['allow']:
            role = self._role_model.get_by_name(rn)
            self.acl.allow(role, method, resource, with_children)
        for rn, method, resource, with_children in self.before_acl['deny']:
            role = self._role_model.get_by_name(rn)
            self.acl.deny(role, method, resource, with_children)
        self.acl.seted = True