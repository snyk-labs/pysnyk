import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pysnyk",
    version="0.0.1",
    author="Snyk.io",
    author_email="support@snyk.io",
    description="A python implementation of the Snyk API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/snyk/pysnyk",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)