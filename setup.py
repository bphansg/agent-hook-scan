"""Setup configuration for agent-hook-scan."""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="agent-hook-scan",
    version="0.1.0",
    description="Scan AI agent configs for risky hooks and over-broad tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Binh Phan",
    author_email="bphansg@users.noreply.github.com",
    url="https://github.com/bphansg/agent-hook-scan",
    license="Apache-2.0",
    packages=find_packages(exclude=["tests", "testdata"]),
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "agent-hook-scan=agent_hook_scan.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="security linter ai agent cursor claude mcp",
)
