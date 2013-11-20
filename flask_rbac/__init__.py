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
