"""
Setup script for ThreatSignal package
This is a legacy setup.py for backward compatibility.
Main configuration is in pyproject.toml.
"""

from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        name="threatsignal",
        version="0.1.0",
        packages=find_packages(),
        python_requires=">=3.10",
    )