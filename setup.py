from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension("linux_keyring._libkeyutils", ["src/linux_keyring/_libkeyutils.pyx"], libraries=["keyutils"]),
]

setup(
    name="linux-keyring",
    ext_modules=cythonize(extensions),
)
