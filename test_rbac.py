import unittest

from flask import Flask, Response, make_response
from flask_login import current_user as login_user

from flask_rbac import RBAC, UserMixin, RoleMixin

import functools


class Role(RoleMixin):
    def __repr__(self):
        return '<Role %s>' % self.name

class User(UserMixin):
    def __repr__(self):
        return '<User %s>' % self.roles

everyone = Role('everyone')
logged_role = Role('logged_role')
staff_role = Role('staff_role')
other_role = Role('other_role')
special = Role('special')

logged_role.add_parent(everyone)
staff_role.add_parents(everyone, logged_role)

anonymous = User(roles=[everyone])
normal_user = User(roles=[logged_role])
staff_role_user = User(roles=[staff_role])
special_user = User(roles=[special])
many_roles_user = User(roles=[logged_role, other_role, everyone])

current_user = anonymous

def rewrite_decorator(viewfunc):
    @functools.wraps(viewfunc)
    def newfunc(*args, **kwargs):
        return viewfunc(*args, **kwargs)
    return newfunc

def makeapp(with_factory, use_white, before_decorator, after_decorator):
    global current_user
    app = Flask(__name__)
    app.debug = True

    if use_white:
        app.config['RBAC_USE_WHITE'] = True
    else:
        app.config['RBAC_USE_WHITE'] = False

    if with_factory:
        rbac = RBAC()
        rbac.init_app(app)
    else:
        rbac = RBAC(app)

    rbac.set_user_loader(lambda: current_user)
    rbac.set_user_model(User)
    rbac.set_role_model(Role)

    @app.route('/')
    @after_decorator
    @rbac.allow(roles=['everyone'], methods=['GET'])
    @before_decorator
    def index():
        return Response('index')

    @app.route('/a')
    @after_decorator
    @rbac.allow(roles=['special'], methods=['GET'])
    @before_decorator
    def a():
        return Response('Hello')

    @app.route('/b', methods=['GET', 'POST'])
    @after_decorator
    @rbac.allow(roles=['logged_role'], methods=['GET'])
    @rbac.allow(roles=['staff_role', 'special'], methods=['POST'])
    @before_decorator
    def b():
        return Response('Hello from /b')

    @app.route('/c')
    @after_decorator
    @rbac.allow(roles=['everyone'], methods=['GET'])
    @rbac.deny(roles=['logged_role'], methods=['GET'], with_children=False)
    @rbac.allow(roles=['staff_role'], methods=['GET'])
    @before_decorator
    def c():
        return Response('Hello from /c')

    @app.route('/d')
    @after_decorator
    @rbac.deny(roles=['everyone'], methods=['GET'])
    @before_decorator
    def d():
        return Response('Hello from /d')

    @app.route('/e')
    @after_decorator
    @rbac.deny(roles=['everyone'], methods=['GET'], with_children=True)
    @before_decorator
    def e():
        return Response('Hello from /e')

    @app.route('/f', methods=['POST'])
    @after_decorator
    @rbac.deny(roles=['logged_role'], methods=['POST'])
    @before_decorator
    def f():
        return Response('Hello from /f')

    @app.route('/g', methods=['GET'])
    @after_decorator
    @rbac.exempt
    @before_decorator
    def g():
        return Response('Hello from /g')

    @app.route('/h', methods=['GET'])
    @after_decorator
    @rbac.allow(['anonymous'], methods=['GET'], with_children=False)
    @before_decorator
    def h():
        return Response('Hello from /h')

    return app


class UseWhiteApplicationUnitTests(unittest.TestCase):

    def setUp(self):
        self.app = makeapp(with_factory=False, use_white=True, before_decorator=rewrite_decorator, after_decorator=rewrite_decorator)
        self.client = self.app.test_client()
        self.rbac = self.app.extensions['rbac'].rbac

    def test_set_user_loader(self):
        global current_user
        self.assertEqual(self.rbac._user_loader(), current_user)
        self.rbac.set_user_loader(lambda: staff_role_user)
        self.assertEqual(self.rbac._user_loader(), staff_role_user)
        # Restore
        self.rbac.set_user_loader(lambda: current_user)

    def test_allow_get_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.open('/').data.decode('utf-8'), 'index')

        current_user = normal_user
        self.assertEqual(self.client.open('/').data.decode('utf-8'), 'index')
        self.assertEqual(self.client.open('/b').data.decode('utf-8'), 'Hello from /b')

        current_user = staff_role_user
        self.assertEqual(self.client.open('/').data.decode('utf-8'), 'index')
        self.assertEqual(self.client.open('/b').data.decode('utf-8'), 'Hello from /b')

        current_user = special_user
        self.assertEqual(self.client.open('/a').data.decode('utf-8'), 'Hello')

    def test_deny_get_view(self):
        global current_user
        current_user = special_user
        self.assertEqual(self.client.open('/').status_code, 403)
        self.assertEqual(self.client.open('/b').status_code, 403)

        current_user = anonymous
        self.assertEqual(self.client.open('/a').status_code, 403)

        current_user = normal_user
        self.assertEqual(self.client.open('/a').status_code, 403)

        current_user = staff_role_user
        self.assertEqual(self.client.open('/a').status_code, 403)

    def test_allow_post_view(self):
        global current_user
        current_user = staff_role_user
        self.assertEqual(self.client.post('/b').data.decode('utf-8'), 'Hello from /b')

        current_user = special_user
        self.assertEqual(self.client.post('/b').data.decode('utf-8'), 'Hello from /b')

    def test_deny_post_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.post('/b').status_code, 403)

        current_user = normal_user
        self.assertEqual(self.client.post('/b').status_code, 403)

    def test_complicate_get_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.open('/c').data.decode('utf-8'), 'Hello from /c')

        current_user = normal_user
        self.assertEqual(self.client.open('/c').status_code, 403)

        current_user = staff_role_user
        self.assertEqual(self.client.open('/c').data.decode('utf-8'), 'Hello from /c')

    def test_hook(self):
        global current_user
        current_user = special_user
        self.rbac.set_hook(lambda: make_response('Permission Denied', 403))
        self.assertEqual(self.client.open('/').status_code, 403)
        self.assertEqual(self.client.open('/').data.decode('utf-8'), 'Permission Denied')

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

        current_user = None
        self.assertTrue(self.rbac.has_permission('GET', 'h'))
        self.assertEqual(self.client.open('/h').data.decode('utf-8'), 'Hello from /h')


    def test_exempt(self):
        global current_user

        current_user = anonymous
        self.assertEqual(self.client.open('/g').data.decode('utf-8'), 'Hello from /g')

        current_user = special_user
        self.assertEqual(self.client.open('/g').data.decode('utf-8'), 'Hello from /g')

        current_user = normal_user
        self.assertEqual(self.client.open('/g').data.decode('utf-8'), 'Hello from /g')


class NoWhiteApplicationUnitTests(unittest.TestCase):

    def setUp(self):
        self.app = makeapp(with_factory=False, use_white=False, before_decorator=rewrite_decorator, after_decorator=rewrite_decorator)
        self.client = self.app.test_client()
        self.rbac = self.app.extensions['rbac'].rbac

    def test_allow_get_view(self):
        global current_user
        current_user = normal_user
        self.assertEqual(self.client.open('/d').data.decode('utf-8'), 'Hello from /d')

        current_user = staff_role_user
        self.assertEqual(self.client.open('/d').data.decode('utf-8'), 'Hello from /d')

    def test_deny_get_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.open('/d').status_code, 403)
        self.assertEqual(self.client.open('/e').status_code, 403)

        current_user = normal_user
        self.assertEqual(self.client.open('/e').status_code, 403)

        current_user = staff_role_user
        self.assertEqual(self.client.open('/e').status_code, 403)

    def test_allow_post_view(self):
        global current_user
        current_user = anonymous
        self.assertEqual(self.client.post('/f').data.decode('utf-8'), 'Hello from /f')

        current_user = staff_role_user
        self.assertEqual(self.client.post('/f').data.decode('utf-8'), 'Hello from /f')

    def test_deny_post_view(self):
        global current_user
        current_user = normal_user
        self.assertEqual(self.client.post('/f').status_code, 403)

    def test_has_permission(self):
        global current_user
        current_user = normal_user
        self.assertTrue(self.rbac.has_permission('GET', 'd'))
        self.assertFalse(self.rbac.has_permission('POST', 'f'))


class RoleMixInUnitTests(unittest.TestCase):

    def test_role_get_name(self):
        self.assertEqual(everyone.get_name(), 'everyone')
        self.assertEqual(logged_role.get_name(), 'logged_role')
        self.assertEqual(staff_role.get_name(), 'staff_role')

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
        logged_role_parents = set()
        staff_role_parents = set()

        for p in everyone.get_parents():
            everyone_parents.add(p)
        for p in logged_role.get_parents():
            logged_role_parents.add(p)
        for p in staff_role.get_parents():
            staff_role_parents.add(p)

        self.assertEqual(everyone_parents, set([]))
        self.assertEqual(logged_role_parents, set([everyone]))
        self.assertEqual(staff_role_parents, set([everyone, logged_role]))

    def test_get_children(self):
        everyone_children = set()
        logged_role_children = set()
        staff_role_children = set()

        for c in everyone.get_children():
            everyone_children.add(c)
        for c in logged_role.get_children():
            logged_role_children.add(c)
        for c in staff_role.get_children():
            staff_role_children.add(c)

        self.assertEqual(everyone_children, set([logged_role, staff_role]))
        self.assertEqual(logged_role_children, set([staff_role]))
        self.assertEqual(staff_role_children, set([]))


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
        staff_role_user_roles = set()
        many_roles_user_roles = set()

        for r in normal_user.get_roles():
            normal_user_roles.add(r)
        for r in staff_role_user.get_roles():
            staff_role_user_roles.add(r)
        for r in many_roles_user.get_roles():
            many_roles_user_roles.add(r)

        self.assertEqual(normal_user_roles, set([logged_role]))
        self.assertEqual(staff_role_user_roles, set([staff_role]))
        self.assertEqual(many_roles_user_roles, set([everyone, logged_role, other_role]))


class DecoratorUnitTests(unittest.TestCase):

    def setUp(self):
        self.rbac = RBAC()

        @self.rbac.as_role_model
        class RoleModel(RoleMixin):
            pass

        @self.rbac.as_user_model
        class UserModel(UserMixin):
            pass

        self.rm = RoleModel
        self.um = UserModel

    def test_as_role_model(self):
        self.assertTrue(self.rbac._role_model is self.rm)

    def test_as_user_model(self):
        self.assertTrue(self.rbac._user_model is self.um)


class DefaultUserLoaderUnitTests(unittest.TestCase):

    def setUp(self):
        self.rbac = RBAC()

    def test_default_user_loader(self):
        self.assertEqual(self.rbac._user_loader(), login_user)
