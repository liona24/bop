from setuptools import setup, find_packages


setup(
    name="bop",
    version="0.0.1",
    packages=find_packages(),
    package_data={
        '': ['*.json']
    },
    install_requires=[
        "cryptography>=2.7",
    ],
    extras_require={
        "debug": ["pytest>=5.3.2"]
    }
)
