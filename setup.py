from setuptools import setup
import os

requirements = os.path.join(os.path.dirname(__file__), 'requirements.txt')

setup(
    name='uvoauth',
    version='0.8',
    description='Oauth client for uvhttp',
    url='https://github.com/justinbarrick/uvoauth',
    packages=['uvoauth'],
    install_requires=[ r.rstrip() for r in open(requirements).readlines() ]
)
