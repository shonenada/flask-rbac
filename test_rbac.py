import unittest

from flask import Flask, Response

from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __repr__(self):
        return '%s' % self.name


class User(UserMixin):
    def add_role(self, role):
        self.roles.updates([role])


everyone = Role('everyone')
local_user = Role('local_user')
staff = Role('staff')
other_role = Role('other_role')

local_user.add_parent(everyone)
staff.add_parents(everyone, local_user)

normal_user = User(roles=[local_user])
staff_user = User(roles=[staff])
many_roles_user = User(roles=[local_user, other_role, everyone])


def makeapp(with_factory=False, use_white=False):
    app = Flask(__name__)
    app.debug = True

    if use_white:
        app.config['RBAC_USE_WHITE'] = True

    if with_factory:
        rbac = RBAC()
        rbac.init_app(app)
    else:
        rbac = RBAC(app)

    @app.route('/')
    def index():
        return Response('index')

    @app.route('/a')
    @rbac.allow('local_user', methods=['GET'])
    def a():
        return Response('Hello')

    @app.route('/b', methods=['GET', 'POST'])
    @rbac.allow('local_user', methods=['GET', 'POST'])
    def b():
        return Response('Hello')

    @app.route('/c')
    def c():
        return Response('Never permit to view this page.')


class RoleMixInUnitTests(unittest.TestCase):

    def test_role_get_name(self):
        self.assertEqual(everyone.get_name(), 'everyone')
        self.assertEqual(local_user.get_name(), 'local_user')
        self.assertEqual(staff.get_name(), 'staff')

    def test_add_parent(self):
        normal_role = Role('normal')
        base_role = Role('base')
        normal_role.add_parent(base_role)
        
        self.assertIn(base_role, normal_role.parents)

    def test_add_parents(self):
        normal_role = Role('normal')
        parent_role = Role('parent')
        another_parent_role = Role('another_parent')
        normal_role.add_parents(parent_role, another_parent_role)
        
        self.assertIn(parent_role, normal_role.parents)
        self.assertIn(another_parent_role, normal_role.parents)

    def test_get_family(self):
        everyone_parents = set()
        local_user_parents = set()
        staff_parents = set()
        
        for p in everyone.get_family():
            everyone_parents.add(p)
        for p in local_user.get_family():
            local_user_parents.add(p)
        for p in staff.get_family():
            staff_parents.add(p)
        
        self.assertEqual(everyone_parents, set([everyone]))
        self.assertEqual(local_user_parents, set([everyone, local_user]))
        self.assertEqual(staff_parents, set([everyone, local_user, staff]))


class UserMixInTests(unittest.TestCase):

    def test_get_roles(self):
        normal_user_roles = set()
        staff_user_roles = set()
        many_roles_user_roles = set()

        for r in normal_user.get_roles():
            normal_user_roles.add(r)
        for r in staff_user.get_roles():
            staff_user_roles.add(r)
        for r in many_roles_user.get_roles():
            many_roles_user_roles.add(r)
        
        self.assertEqual(normal_user_roles, set([everyone, local_user]))
        self.assertEqual(staff_user_roles, set([everyone, local_user, staff]))
        self.assertEqual(many_roles_user_roles, set([everyone, local_user, other_role]))
