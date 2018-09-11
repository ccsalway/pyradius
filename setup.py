from setuptools import setup, find_packages

setup(
    name='snakeRadius',
    version='1.0',
    packages=find_packages(),
    install_requires=['six', 'netaddr'],
    url='https://github.com/ccsalway/pyradius',
    license='MIT',
    author='Christian Salway',
    author_email='ccsalway@yahoo.co.uk',
    description='Radius Server written in Python',
    classifiers=[
        "Operating System :: OS Independent",
    ]
)
