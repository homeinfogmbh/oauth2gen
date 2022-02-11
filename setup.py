#! /usr/bin/env python3
"""Install script."""

from setuptools import setup


setup(
    name='oauth2gen',
    use_scm_version={
        "local_scheme": "node-and-timestamp"
    },
    setup_requires=['setuptools_scm'],
    author='HOMEINFO - Digitale Informationssysteme GmbH',
    author_email='<info@homeinfo.de>',
    maintainer='Richard Neumann',
    maintainer_email='<r.neumann@homeinfo.de>',
    install_requires=[
        'argon2_cffi',
        'authlib',
        'flask',
        'peewee',
        'peeweeplus',
        'wsgilib'
    ],
    packages=[
        'oauth2gen',
        'oauth2gen.oauth2'
    ],
    description='OAuth2 authentication framework generator.'
)
