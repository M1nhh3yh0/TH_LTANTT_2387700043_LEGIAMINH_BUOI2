from setuptools import setup, find_packages

setup(
    name="securecrypto",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "argon2-cffi",
        "flask",
    ],
    entry_points={
        "console_scripts": [
            "securecrypto-cli=securecrypto.cli:main",
        ]
    },
)
