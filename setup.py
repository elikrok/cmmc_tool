# setup.py
from setuptools import setup, find_packages

setup(
    name="cmmc-compliance-tool",
    version="1.0.0",
    description="CMMC 2.0 Level 1 Network Compliance Checker",
    author="Your Name",
    author_email="your.email@domain.com",
    packages=find_packages(),
    install_requires=[
        "pathlib2>=2.3.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "bandit>=1.7.5",
        ]
    },
    entry_points={
        "console_scripts": [
            "cmmc-tool=main_gui:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.11",
)
