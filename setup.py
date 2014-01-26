from setuptools import setup


setup(
    name='Flask-RBAC',
    version='0.1.0',
    url='https://github.com/shonenada/flask-rbac',
    author='Yaoda Liu',
    author_email='shonenada@gmail.com',
    description='RBAC support for Flask',
    zip_safe=False,
    packages=['flask_rbac'],
    include_package_data=True,
    platforms='any',
    install_requires=['Flask>=0.10'],
    classifiers=[
        'Framework :: Flask',
        'Environment :: Web Environment',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
