class RoleMixin(object):
    '''
    Thiss mixin class provides implementations for the methods of Role model
    needed by Flask-RBAC
    '''

    roles = {}

    def __init__(self, name=None):
        self.name = name
        if not hasattr(self.__class__, 'parents'):
            self.parents = set()
        if not hasattr(self.__class__, 'children'):
            self.children = set()
        RoleMixin.roles[name] = self

    def get_name(self):
        '''Return the name of this role'''
        return self.name

    def add_parent(self, parent):
        parent.children.add(self)
        self.parents.add(parent)

    def add_parents(self, *ps):
        for parent in ps:
            self.add_parent(parent)

    def get_parents(self):
        '''Return parents of this role'''
        for parent in self.parents:
            yield parent
            for grandparent in parent.get_parents():
                yield grandparent

    def get_children(self):
        '''Return children of this role'''
        for child in self.children:
            yield child
            for grandchild in child.get_children():
                yield grandchild

    @staticmethod
    def get_by_name(name):
        return RoleMixin.roles[name]


class UserMixin(object):
    '''
    This mixin class provides implementations for the methods of User model
    needed by Flask-RBAC.
    '''

    def __init__(self, roles=[]):
        self.roles = set(roles)

    def add_role(self, role):
        self.add_roles([role])

    def add_roles(self, roles):
        self.roles.update(roles)

    def get_roles(self):
        for role in self.roles:
            yield role


anonymous = RoleMixin('anonymous')
