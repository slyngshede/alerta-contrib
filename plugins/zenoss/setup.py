
from setuptools import setup, find_packages

version = '1.0.1'

setup(
    name="alerta-zenoss",
    version=version,
    description='Alerta plugin for Zenoss',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Simon Lyngshede',
    author_email='sl@netic.dk',
    packages=find_packages(),
    py_modules=['alerta_zenoss'],
    install_requires=[
        'requests'
    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'zenoss = alerta_zenoss:ZenossHandler'
        ]
    }
)
