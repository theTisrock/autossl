from setuptools import setup, find_packages
from autossl import version

with open('./README.md', "r") as f:
    long_description = f.read()

setup(
    name='autocert',
    version=version,
    packages=find_packages(),
    install_requires=[
        'cryptography',
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="thetisrock",
    description="Automate your SSL certificate workflows."
)
