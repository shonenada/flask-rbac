class RoleMixin(object):
    '''
    Thiss mixin class provides implementations for the methods of Role model
    needed by Flask-RBAC
    '''

    def __init__(self, name):
        self.name = name
        self.parents = set()

    def get_name(self):
        '''Return the name of this role'''
        return self.name

    def add_parent(self, parent):
        self.parents.add(parent)

    def add_parents(self, *ps):
        for parent in ps:
            self.add_parent(parent)

    def get_family(self):
        '''Return family of this role'''
        yield self
        for parent in self._get_parents():
            yield parent

    def _get_parents(self):
        '''Iterate parent and grandparents of this role'''
        for parent in self.parents:
            yield parent
            for grandparent in parent._get_parents():
                yield grandparent


class UserMixin(object):
    '''
    This mixin class provides implementations for the methods of User model
    needed by Flask-RBAC.
    '''

    def __init__(self, roles=[]):
        self.roles = roles

    def get_roles(self):
        for role in self.roles:
            for r in role.get_family():
                yield r
