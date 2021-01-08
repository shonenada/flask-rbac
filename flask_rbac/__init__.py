# -*-coding: utf-8
"""
    flaskext.rbac
    ~~~~~~~~~~~~~

    Adds Role-based Access Control modules to application
"""

import itertools
from collections import defaultdict

from flask import request, abort, _request_ctx_stack

try:
    from flask import _app_ctx_stack
except ImportError:
    _app_ctx_stack = None

try:
    from flask_login import (current_user,
                             AnonymousUserMixin as anonymous_model)
except ImportError:
    current_user, anonymous_model = None, None

from .model import RoleMixin, UserMixin, anonymous


__all__ = ['RBAC', 'RoleMixin', 'UserMixin']


connection_stack = _app_ctx_stack or _request_ctx_stack


class AccessControlList(object):
    """
    This class record rules for access controling.
    """

    def __init__(self):
        self._allowed = []
        self._denied = []
        self._exempt = []
        self.seted = False

    def allow(self, role, method, resource, with_children=True):
        """Add allowing rules.

        :param role: Role of this rule.
        :param method: Method to allow in rule, include GET, POST, PUT etc.
        :param resource: Resource also view function.
        :param with_children: Allow role's children in rule as well
                              if with_children is `True`
        """
        if with_children:
            for r in role.get_children():
                permission = (r.get_name(), method, resource)
                if permission not in self._allowed:
                    self._allowed.append(permission)
        if role == 'anonymous':
            permission = (role, method, resource)
        else:
            permission = (role.get_name(), method, resource)
        if permission not in self._allowed:
            self._allowed.append(permission)

    def deny(self, role, method, resource, with_children=False):
        """Add denying rules.

        :param role: Role of this rule.
        :param method: Method to deny in rule, include GET, POST, PUT etc.
        :param resource: Resource also view function.
        :param with_children: Deny role's children in rule as well
                              if with_children is `True`
        """
        if with_children:
            for r in role.get_children():
                permission = (r.get_name(), method, resource)
                if permission not in self._denied:
                    self._denied.append(permission)
        permission = (role.get_name(), method, resource)
        if permission not in self._denied:
            self._denied.append(permission)

    def exempt(self, resource):
        """Exempt a view function from being checked permission

        :param resource: The view function exempt from checking.
        """
        if resource not in self._exempt:
            self._exempt.append(resource)

    def is_allowed(self, role, method, resource):
        """Check whether role is allowed to access resource

        :param role: Role to be checked.
        :param method: Method to be checked.
        :param resource: View function to be checked.
        """
        return (role, method, resource) in self._allowed

    def is_denied(self, role, method, resource):
        """Check wherther role is denied to access resource

        :param role: Role to be checked.
        :param method: Method to be checked.
        :param resource: View function to be checked.
        """
        return (role, method, resource) in self._denied

    def is_exempt(self, resource):
        """Return whether resource is exempted.

        :param resource: View function to be checked.
        """
        return resource in self._exempt


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
        self._user_loader = kwargs.get('user_loader', lambda: current_user)
        self.permission_failed_hook = kwargs.get('permission_failed_hook')

        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        """Initialize application in Flask-RBAC.
        Adds (RBAC, app) to flask extensions.
        Adds hook to authenticate permission before request.

        :param app: Flask object
        """

        app.config.setdefault('RBAC_USE_WHITE', False)
        self.use_white = app.config['RBAC_USE_WHITE']

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['rbac'] = _RBACState(self, app)

        self.acl.allow(anonymous, 'GET', 'static')
        app.before_first_request(self._setup_acl)

        app.before_request(self._authenticate)

    def as_role_model(self, model_cls):
        """A decorator to set custom model or role.

        :param model_cls: Model of role.
        """
        self._role_model = model_cls
        return model_cls

    def as_user_model(self, model_cls):
        """A decorator to set custom model or user.

        :param model_cls: Model of user.
        """
        self._user_model = model_cls
        return model_cls

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

            from flask_login import current_user
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
        app = self.get_app()
        _user = user or self._user_loader()
        if not hasattr(_user, 'get_roles'):
            roles = [anonymous]
        else:
            roles = _user.get_roles()
        return self._check_permission(roles, method, endpoint)

    def allow(self, roles, methods, with_children=True, endpoint=None):
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
            resource = [endpoint or view_func.__name__]
            for r, m, v in itertools.product(roles, _methods, resource):
                self.before_acl['allow'].append((r, m, v, with_children))
            return view_func
        return decorator

    def deny(self, roles, methods, with_children=False, endpoint=None):
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
            resource = [endpoint or view_func.__name__]
            for r, m, v in itertools.product(roles, _methods, resource):
                self.before_acl['deny'].append((r, m, v, with_children))
            return view_func
        return decorator

    def exempt(self, view_func):
        """Exempt a view function from being checked permission.
        It is useful when you are using white list checking.

        Example::

            @app.route('/everyone/can/access')
            @rbac.exempt
            def everyone_can_access():
                return 'Hello~'

        :param view_func: The view function going to be exempted.
        """
        self.acl.exempt(view_func.__name__)
        return view_func

    def get_app(self, reference_app=None):
        """Helper method that implements the logic to look up an application.
        """
        if reference_app is not None:
            return reference_app
        if self.app is not None:
            return self.app
        ctx = connection_stack.top
        if ctx is not None:
            return ctx.app
        raise RuntimeError('application not registered on rbac '
                           'instance and no application bound '
                           'to current context')

    def _authenticate(self):
        app = self.get_app()
        assert app, "Please initialize your application into Flask-RBAC."
        assert self._role_model, "Please set role model before authenticate."
        assert self._user_model, "Please set user model before authenticate."
        assert self._user_loader, "Please set user loader before authenticate."

        current_user = self._user_loader()

        # Compatible with flask-login anonymous user
        if hasattr(current_user, '_get_current_object'):
            current_user = current_user._get_current_object()

        if (current_user is not None
                and not isinstance(current_user,
                                   (self._user_model, anonymous_model))):
            raise TypeError(
                "%s is not an instance of %s" %
                (current_user, self._user_model.__class__))

        resource = request.endpoint
        if not resource:
            abort(404)

        method = request.method

        if not hasattr(current_user, 'get_roles'):
            roles = [anonymous]
        else:
            roles = current_user.get_roles()

        permit = self._check_permission(roles, method, resource)

        if not permit:
            return self._deny_hook()

    def _check_permission(self, roles, method, resource):

        if self.acl.is_exempt(resource):
            return True

        _roles = set()
        _methods = set(['*', method])
        _resources = set([None, resource])

        if self.use_white:
            _roles.add(anonymous)

        is_allowed = None
        _roles.update(roles)

        if not self.acl.seted:
            self._setup_acl()

        for r, m, res in itertools.product(_roles, _methods, _resources):
            if self.acl.is_denied(r.get_name(), m, res):
                return False

            if not is_allowed and self.acl.is_allowed(r.get_name(), m, res):
                is_allowed = True
                break

        if self.use_white:
            permit = (is_allowed is True)
        else:
            permit = (is_allowed is not False)

        return permit

    def _deny_hook(self):
        if self.permission_failed_hook:
            return self.permission_failed_hook()
        else:
            abort(403)

    def _setup_acl(self):
        for rn, method, resource, with_children in self.before_acl['allow']:
            role = self._role_model.get_by_name(rn)
            if rn == 'anonymous':
                role = anonymous
            else:
                role = self._role_model.get_by_name(rn)
            self.acl.allow(role, method, resource, with_children)

        if not self.use_white:
            to_deny_map = defaultdict(list)
            all_roles = {x.get_name() if not isinstance(x, str)
                    else x for x in self._role_model.get_all()}

            for role, method, resource, with_children in self.before_acl['allow']:
                to_deny_map[(resource, role, with_children)].append(method)
            for k, methods in to_deny_map.items():
                view, role, with_children, = k
                for r, m in itertools.product(all_roles - {role}, methods):
                    rule = (r, m, view, with_children)
                    if rule not in self.before_acl['allow']:
                        self.before_acl['deny'].append(rule)

        for rn, method, resource, with_children in self.before_acl['deny']:
            role = self._role_model.get_by_name(rn)
            self.acl.deny(role, method, resource, with_children)
        self.acl.seted = True
