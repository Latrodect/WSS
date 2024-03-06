from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='serpant',
    version='1.1.2',
    description='A CLI tool for scanning directories for vulnerabilities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Bahadir Nural',
    author_email='bahadir.nural@outlook.com',
    url='https://github.com/Latrodect/wss-repo-vulnerability-finder',
    packages=find_packages(),
    install_requires=[
        'termcolor',
        'colorlog',
        'alive-progress'
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
