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
    def get_name(self):
        return self.name

    def get_parents(self):
        return self.parents


class RBACUserMixin(object):
    '''
    This mixin class provides implementations for the methods of User model
    needed by Flask-RBAC.
    '''
    def get_roles(self):
        return self.roles


class _RBACState(object):
    '''Records configuration for Flask-RBAC'''
    def __init__(self, rbac, app):
        self.rbac = rbac
        self.app = app


class RBAC(object):
    '''
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
        self.app = app

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['rbac'] = _RBACState(self, app)

        app.before_request(self._authenticate)

    def set_role_model(model):
        if not ('get_name' in dir(model) and 'get_parents' in dir(model)):
            raise NotImplementedError(
                "%s didn't implement 'get_name' or 'get_parents' methods!" %
                model.__class__)
        self._role_model = model

    def set_user_model(model):
        if not 'get_roles' in dir(model):
            raise NotImplementedError(
                "%s didn't implement 'get_roles' method!" % model.__class__)
        self._user_model = model

    def set_user_loader(loader):
        self._user_loader = loader

    def _authenticate(self):
        '''Authenticate permission'''
        pass
