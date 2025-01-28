from setuptools import setup, find_packages

setup(
    name="anket",
    version="2.0",
    description="Anket: a tool to find Indicators of Compromise (IOC) and track malware activity.",
    author="5aslu",
    author_email="redrabytes@mailfence.com",
    url="https://github.com/redrabytes/anket",
    packages=find_packages(),
    install_requires=[
        "argparse",
        "colorama",
        "whois",
        "logging",
        "debugpy",
        "argparse",
    ],
    entry_points={
        'console_scripts': [
            'anket = anket.core:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
