import setuptools


with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="s-vault",
    version="0.0.2",
    author="Eldad Bishari",
    author_email="eldad@1221tlv.org",
    description="Simple vault server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/eldad1221/s-vault",
    packages=setuptools.find_packages(),
    install_requires=[
        'quickbe==0.0.6',
        'GitPython==3.1.24',
        'cryptography==35.0.0',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
