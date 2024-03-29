This documents show how to create Flask-RBAC extension easily and quickly.


Configuration Your Application
------------------------------

As same as many Flask extensions, you need to configuration your application::

    from flask import Flask
    from flask_rbac import RBAC

    app = Flask(__name__)
    rbac = RBAC(app)

or you can configuration using factory method::

    from flask import Flask
    from flask_rbac import RBAC

    rbac = RBAC()

    def create_app():
        app = Flask(__name__)

        rbac.init_app(app)

        return app

Mode Setting
------------

There are two modes for Flask-RBAC, `RBAC_USE_WHITE` decide whether use
white list to check the permission. And it set `False` to default.

============================ ================================================
 `RBAC_USE_WHITE = True`     Only allowing rules can access the resources.
                             This means, all deny rules and rules
                             you did not add cannot access the resources.
 `RBAC_USE_WHITE = False`    Only denying rules cannot access the resources.
                             In case you set an allow rule, denying rules will
                             also be automatically created for existing
                             non-added roles in this route.
============================ ================================================

Change it using::

    app.config['RBAC_USE_WHITE'] = True


Set Role Model
--------------

Flask-RBAC implements some methods need by Flask-RBAC in RoleMixin_ class.
You can use RoleMixin as your role model::

    class Role(RoleMixin):
        pass

    anonymous = Role('anonymous')

However, if your application is working under SQLAlchemy,
and you want to save the roles in database, you need to override
the Role class to adapt your application, here is an example::

    from flask_rbac import RoleMixin
    from your_package.app import db

    roles_parents = db.Table(
        'roles_parents',
        db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
        db.Column('parent_id', db.Integer, db.ForeignKey('role.id'))
    )

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(20))
        parents = db.relationship(
            'Role',
            secondary=roles_parents,
            primaryjoin=(id == roles_parents.c.role_id),
            secondaryjoin=(id == roles_parents.c.parent_id),
            backref=db.backref('children', lazy='dynamic')
        )

        def __init__(self, name):
            RoleMixin.__init__(self)
            self.name = name

        def add_parent(self, parent):
            # You don't need to add this role to parent's children set,
            # relationship between roles would do this work automatically
            self.parents.append(parent)

        def add_parents(self, *parents):
            for parent in parents:
                self.add_parent(parent)

        @staticmethod
        def get_by_name(name):
            return Role.query.filter_by(name=name).first()

After create role model, you can add your model to Flask-RBAC::

    rbac.set_role_model(Role)

Or use decorator to set role model for Flask-RBAC::

    @rbac.as_role_model
    class Role(RoleMixin):
        # codes go here


Set User Model
--------------

Same as the RoleMixin, UserMixin_ implements some methods for Flask-RBAC,
You can extend it directly::

    from flask_rbac import UserMixin

    class User(UserMixin):
        pass

    a_user = User()

Well, if your application works under SQLAlchemy::

    from flask_rbac import UserMixin
    from your_package.app import db

    users_roles = db.Table(
        'users_roles',
        db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
    )

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(30), unllable=True)
        # Other columns
        roles = db.relationship(
            'Role',
            secondary=users_roles,
            backref=db.backref('roles', lazy='dynamic')
        )

        def add_role(self, role):
            self.roles.append(role)

        def add_roles(self, roles):
            for role in roles:
                self.add_role(role)

        def get_roles(self):
            for role in self.roles:
                yield role

Same as role model, you should add user model to Flask-RBAC::

    rbac.set_user_model(User)

Or using decorator::

    @rbac.as_user_model
    class User(UserMixin):
        # codes go here


Set User Loader
---------------

Flask-RBAC need to know who is current user, so it requires you to provide a
function which tells it who is current user.

Flask-RBAC will load current user from `Flask-Login`_ if you have install it
by default.

If you save current user in
`flask.g`, here is an example for you::

    from flask import g, current_app

    @app.route('/signin', methods=['POST'])
    @rbac.allow(['anonymous'], methods=['POST'])
    def signin():
        # Sign in logic...
        g.current_user = user

    def get_current_user():
        with current_app.request_context():
            return g.current_user

    rbac.set_user_loader(get_current_user)


Set Access Rules
----------------

You can use `allow` and `deny` to add rules to Flask-RBAC::

    @app.route('/')
    @rbac.allow(['anonymous'], methods=['GET'])
    def index():
        # your codes.
        pass

    @app.route('/account/signin', methods=['GET', 'POST'])
    @rbac.deny(['logged_user'], methods=['GET', 'POST'])
    def signin():
        # show sign in page or handle sign in request.
        pass


The code above adding two rules:

- Allows user of *anonymous* role to *GET* /.

- Deny user of *logged_user* role to *GET* and *POST* */account/signin*.

`Flask`_ itself assumes the name of the view function as the endpoint for the
registered URL rule, that's why in rules validation by default we use the decorated function
name to check against the endpoint of the input request. But, in case you specified
a different endpoint or you use the decorators inside a blueprint or
abstracted blueprints extensions like `Flask-Admin`_ you can directly specify to the decorator
the endpoint used in your route.

.. code-block:: python

    @app.route('/signin', methods=['GET', 'POST'], endpoint='account.signin')
    @rbac.deny(['logged_user'], methods=['GET', 'POST'],
        endpoint='account.signin')
    def signin():
        # show sign in page or handle sign in request.
        pass


.. _RoleMixin: api.html#flask-ext-rbac-model-rolemixin
.. _UserMixin: api.html#flask-ext-rbac-model-usermixin
.. _Flask-Login: https://flask-login.readthedocs.org/en/latest/
.. _Flask: https://flask-admin.readthedocs.io/en/latest/introduction/?highlight=endpoint#generating-urls
.. _Flask-Admin: https://flask-admin.readthedocs.io/en/latest/introduction/?highlight=endpoint#generating-urls
