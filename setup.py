from setuptools import setup, find_packages
from autossl import version

setup(
    name='autocert',
    version=version,
    packages=find_packages(),
    install_requires=[
        'cryptography',
    ]
)
