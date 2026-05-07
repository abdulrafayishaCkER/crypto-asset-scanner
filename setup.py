from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="crypto-recon",
    version="2.1.0",
    author="CryptoRecon Team",
    description="CBOM discovery tool for cryptographic assets and secrets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/abdulrafayishaCkER/crypto-asset-scanner",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "sslyze>=5.2.0",
        "rich>=13.0.0",
        "dnspython>=2.4.0",
        "beautifulsoup4>=4.12.0",
        "tomli>=2.0.0; python_version<'3.11'",
    ],
    entry_points={
        "console_scripts": [
            "cryptorecon=crypto_recon.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security scanner tls certificate secrets recon",
)
