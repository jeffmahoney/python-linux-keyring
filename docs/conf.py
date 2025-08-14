import os
import sys
from datetime import datetime

project = "linux-keyutils"
author = "Jeff Mahoney"
version = release = "1.6.3.0"
copyright = f"{datetime.now():%Y}, {author}"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx_autodoc_typehints",
    "sphinx.ext.intersphinx",
]
autosummary_generate = False
autodoc_typehints = "description"
autodoc_class_signature = "separated"
templates_path = ["_templates"]
exclude_patterns = []
html_theme = "alabaster"
html_static_path = ["_static"]

# Ensure src/ is importable
sys.path.insert(0, os.path.abspath("../src"))

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", {}),
}
