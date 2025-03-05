from setuptools import setup, find_packages

setup(
    name="nidhogg",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "crosshair-tool>=0.0.82",
    ],
    entry_points={
        'console_scripts': [
            'nidhogg=nidhogg.main:main',
        ],
    },
)