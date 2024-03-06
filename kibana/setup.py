from setuptools import setup

setup(
    name="detection-rules-kibana",
    version="0.1.0",
    py_modules=["connector", "resources"],
    install_requires=[
        "requests>=2.25,<3.0",
        "elasticsearch~=8.1",
    ]
)
