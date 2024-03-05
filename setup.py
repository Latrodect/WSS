from setuptools import setup, find_packages

setup(
    name='serpant',
    version='1.0.0',
    description='A CLI tool for scanning directories for vulnerabilities',
    long_description='A CLI tool for scanning directories for vulnerabilities such as hardcoded passwords, exposed API keys, etc.',
    author='Bahadir Nural',
    author_email='bahadir.nural@outlook.com',
    url='https://github.com/Latrodect/wss-repo-vulnerability-finder',
    packages=find_packages(),
    install_requires=[
        'termcolor',
        'colorlog'
    ],
    entry_points={
        'console_scripts': [
            'serpant=src.cli:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
