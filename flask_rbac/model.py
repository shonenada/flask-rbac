class RoleMixin(object):
    """This provides implementations for the methods that Flask-RBAC wants
    the role model to have.

    :param name: The name of role.
    """

    roles = {}

    def __init__(self, name=None):
        self.name = name
        if not hasattr(self.__class__, 'parents'):
            self.parents = set()
        if not hasattr(self.__class__, 'children'):
            self.children = set()
        RoleMixin.roles[name] = self

    def get_name(self):
        """Return the name of this role"""
        return self.name

    def add_parent(self, parent):
        """Add a parent to this role,
        and add role itself to the parent's children set.
        you should override this function if neccessary.

        Example::

            logged_user = RoleMixin('logged_user')
            student = RoleMixin('student')
            student.add_parent(logged_user)

        :param parent: Parent role to add in.
        """
        parent.children.add(self)
        self.parents.add(parent)

    def add_parents(self, *parents):
        """Add parents to this role. Also should override if neccessary.
        Example::

            editor_of_articles = RoleMixin('editor_of_articles')
            editor_of_photonews = RoleMixin('editor_of_photonews')
            editor_of_all = RoleMixin('editor_of_all')
            editor_of_all.add_parents(editor_of_articles, editor_of_photonews)

        :param parents: Parents to add.
        """
        for parent in parents:
            self.add_parent(parent)

    def get_parents(self):
        for parent in self.parents:
            yield parent
            for grandparent in parent.get_parents():
                yield grandparent

    def get_children(self):
        for child in self.children:
            yield child
            for grandchild in child.get_children():
                yield grandchild

    @staticmethod
    def get_by_name(name):
        """A static method to return the role which has the input name.

        :param name: The name of role.
        """
        return RoleMixin.roles[name]

    @classmethod
    def get_all(cls):
        """Return all existing roles
        """
        return cls.roles


class UserMixin(object):
    """This provides implementations for the methods that Flask-RBAC wants
    the user model to have.

    :param roles: The roles of this user should have.
    """

    def __init__(self, roles=[]):
        self.roles = set(roles)

    def add_role(self, role):
        """Add a role to this user.

        :param role: Role to add.
        """
        self.roles.add(role)

    def add_roles(self, *roles):
        """Add roles to this user.

        :param roles: Roles to add.
        """
        for role in roles:
            self.add_role(role)

    def get_roles(self):
        for role in self.roles:
            yield role


anonymous = RoleMixin('anonymous')
