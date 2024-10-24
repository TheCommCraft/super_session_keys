from setuptools import setup, find_packages
import os

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()
    
VERSION = '0.1.1'

setup(
    name='super_session_keys',
    version=VERSION,
    author='TheCommCraft',
    author_email='simon.c.gilde@gmail.com',
    description='A python module for super session keys',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/TheCommCraft/super_session_keys',
    packages=find_packages(exclude=[]),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords=[],
    install_requires=[
        'cryptography',
        'cachetools',
        'requests',
        'Flask'
    ],
    python_requires='>=3.6',
)
