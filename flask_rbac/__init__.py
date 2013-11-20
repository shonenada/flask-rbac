#-*- coding: utf-8 -*-
"""
    flaskext.rbac
    ~~~~~~~~~~~~~

    Adds Role-based Access Control module to application.

"""
class RBACRoleMixin(object):
    '''
    This mixin class provides implementations for the methods of Role model
    needed by Flask-RBAC.
    '''
    @staticmethod
    def get_roles(self):
        '''A static method return a list of all roles'''
        return self.query.all()

    def get_name(self):
        '''Return the name of this role'''
        return self.name

    def get_parents(self):
        '''Return parents of this role'''
        return self.parents


class RBACUserMixin(object):
    '''
    This mixin class provides implementations for the methods of User model
    needed by Flask-RBAC.
    '''
    def get_roles(self):
        '''Return roles of this user'''
        return self.roles


class AccessControl(object):
    '''
    This class record data for access controling.
    '''
    def __init__(self):
        self._resource = {}
        self._allowed = {}
        self._denied = {}

    def allow(self, role, resource, method, assertion=None):
        pass

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
        self._role_model = kwargs.get('role_model', None)
        self._user_model = kwargs.get('user_model', None)
        self._user_loader = kwargs.get('user_loader', None)

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

        app.before_request(self._authenticate)

    def set_role_model(model):
        '''Set custom model of Role.'''
        needed_methods = ['get_roles', 'get_name', 'get_parents']
        for method in needed_methods:
            if not method in dir(model):
                raise NotImplementedError("%s didn't implement %s method!" %
                                          model.__class__, method)
        self._role_model = model

    def set_user_model(model):
        '''Set custom model of User.'''
        needed_methods = ['get_roles']
        for method in needed_methods:
            if not method in dir(model):
                raise NotImplementedError("%s didn't implement %s method!" %
                                          model.__class__, method)
        self._user_model = model

    def set_user_loader(loader):
        '''Set user loader, which is used to load current user'''
        self._user_loader = loader

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
