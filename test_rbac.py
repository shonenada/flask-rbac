import unittest

from flask import Flask, Response, make_response

from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __repr__(self):
        return '<Role %s>' % self.name

class User(UserMixin):
    def __repr__(self):
        return '<User %s>' % self.roles

everyone = Role('everyone')
local_user = Role('local_user')
staff = Role('staff')
other_role = Role('other_role')
special = Role('special')

local_user.add_parent(everyone)
staff.add_parents(everyone, local_user)

anonymous = User(roles=[everyone])
normal_user = User(roles=[local_user])
staff_user = User(roles=[staff])
special_user = User(roles=[special])
many_roles_user = User(roles=[local_user, other_role, everyone])

current_user = anonymous


def makeapp(with_factory=False, use_white=False):
    global current_user
    app = Flask(__name__)
    app.debug = True

    if use_white:
        app.config['RBAC_USE_WHITE'] = True

    if with_factory:
        rbac = RBAC()
        rbac.init_app(app)
    else:
        rbac = RBAC(app)

    rbac.set_user_loader(lambda: current_user)
    rbac.set_user_model(User)
    rbac.set_role_model(Role)

    @app.route('/')
    @rbac.allow(roles=[everyone], methods=['GET'])
    def index():
        return Response('index')

    @app.route('/a')
    @rbac.allow(roles=[special], methods=['GET'])
    def a():
        return Response('Hello')

    @app.route('/b', methods=['GET', 'POST'])
    @rbac.allow(roles=[local_user], methods=['GET'])
    @rbac.allow(roles=[staff, special], methods=['POST'])
    def b():
        return Response('Hello from /b')

    @app.route('/c')
    @rbac.allow(roles=[everyone], methods=['GET'])
    @rbac.deny(roles=[local_user], methods=['GET'], with_children=False)
    @rbac.allow(roles=[staff], methods=['GET'])
    def c():
        return Response('Hello from /c')

    return app


class UseWhiteApplicationUnitTests(unittest.TestCase):

    def setUp(self):
        self.app = makeapp(use_white=True)
        self.client = self.app.test_client()
        self.rbac = self.app.extensions['rbac'].rbac

    def test_set_user_loader(self):
        global current_user
        self.assertEqual(self.rbac._user_loader(), current_user)
        self.rbac.set_user_loader(lambda: staff_user)
        self.assertEqual(self.rbac._user_loader(), staff_user)
        # Restore
        self.rbac.set_user_loader(lambda: current_user)

    def test_allow_get_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.open('/').data, 'index')
        current_user = normal_user
        self.assertEqual(self.client.open('/').data, 'index')
        self.assertEqual(self.client.open('/b').data, 'Hello from /b')
        current_user = staff_user
        self.assertEqual(self.client.open('/').data, 'index')
        self.assertEqual(self.client.open('/b').data, 'Hello from /b')
        current_user = special_user
        self.assertEqual(self.client.open('/a').data, 'Hello')

    def test_deny_get_view(self):
        global current_user
        current_user = special_user
        self.assertEqual(self.client.open('/').status_code, 403)
        self.assertEqual(self.client.open('/b').status_code, 403)
        current_user = anonymous
        self.assertEqual(self.client.open('/a').status_code, 403)
        current_user = normal_user
        self.assertEqual(self.client.open('/a').status_code, 403)
        current_user = staff_user
        self.assertEqual(self.client.open('/a').status_code, 403)

    def test_allow_post_view(self):
        global current_user
        current_user = staff_user
        self.assertEqual(self.client.post('/b').data, 'Hello from /b')
        current_user = special_user
        self.assertEqual(self.client.post('/b').data, 'Hello from /b')

    def test_deny_post_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.post('/b').status_code, 403)
        current_user = normal_user
        self.assertEqual(self.client.post('/b').status_code, 403)

    def test_complicate_get_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.open('/c').data, 'Hello from /c')
        current_user = normal_user
        self.assertEqual(self.client.open('/c').status_code, 403)
        current_user = staff_user
        self.assertEqual(self.client.open('/c').data, 'Hello from /c')

    def test_hook(self):
        global current_user
        current_user = special_user
        self.rbac.set_hook(lambda: make_response('Permission Denied', 403))
        self.assertEqual(self.client.open('/').status_code, 403)
        self.assertEqual(self.client.open('/').data, 'Permission Denied')

    def test_has_permission(self):
        global current_user
        
        current_user = anonymous
        self.assertTrue(self.rbac.has_permission('GET', 'index'))
        self.assertTrue(self.rbac.has_permission('GET', 'c'))
        self.assertFalse(self.rbac.has_permission('GET', 'a'))
        self.assertFalse(self.rbac.has_permission('POST', 'index'))
        
        current_user = special_user
        self.assertTrue(self.rbac.has_permission('GET', 'a'))
        self.assertTrue(self.rbac.has_permission('POST', 'b'))
        self.assertFalse(self.rbac.has_permission('GET', 'c'))

        current_user = anonymous
        self.assertTrue(self.rbac.has_permission('POST', 'b', special_user))


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

    def test_get_parents(self):
        everyone_parents = set()
        local_user_parents = set()
        staff_parents = set()
        
        for p in everyone.get_parents():
            everyone_parents.add(p)
        for p in local_user.get_parents():
            local_user_parents.add(p)
        for p in staff.get_parents():
            staff_parents.add(p)
        
        self.assertEqual(everyone_parents, set([]))
        self.assertEqual(local_user_parents, set([everyone]))
        self.assertEqual(staff_parents, set([everyone, local_user]))

    def test_get_children(self):
        everyone_children = set()
        local_user_children = set()
        staff_children = set()
        
        for c in everyone.get_children():
            everyone_children.add(c)
        for c in local_user.get_children():
            local_user_children.add(c)
        for c in staff.get_children():
            staff_children.add(c)
        
        self.assertEqual(everyone_children, set([local_user, staff]))
        self.assertEqual(local_user_children, set([staff]))
        self.assertEqual(staff_children, set([]))


class UserMixInUnitTests(unittest.TestCase):

    def test_add_role(self):
        new_role = Role('new_for_test')
        another_role = Role('for_test')
        the_third_role = Role('The_third_man')

        user_one = User()
        user_two = User()
        user_three = User()

        user_one.add_role(another_role)
        user_three.add_role(new_role)
        user_three.add_role(another_role)

        self.assertEqual(user_one.roles, set([another_role]))
        self.assertEqual(user_two.roles, set([]))
        self.assertEqual(user_three.roles, set([new_role, another_role]))

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
        
        self.assertEqual(normal_user_roles, set([local_user]))
        self.assertEqual(staff_user_roles, set([staff]))
        self.assertEqual(many_roles_user_roles, set([everyone, local_user, other_role]))
