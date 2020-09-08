from setuptools import setup


setup(
    name="bop",
    version="0.0.1",
    packages=["bop"],
    install_requires=[
        "cryptography>=2.7",
    ],
    extras_require={
        "debug": ["pytest>=5.3.2"]
    }
)

