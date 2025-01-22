# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys

project = 'sym-DFS-project'
copyright = '2025, Carlo Uguzzoni'
author = 'Carlo Uguzzoni'
release = '1.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',               # Genera documentazione dalle docstring.
    'sphinx.ext.viewcode',              # Collega il codice sorgente.
    'sphinx.ext.inheritance_diagram',   # Diagrammi delle classi.
    'sphinx.ext.graphviz',              # Diagrammi con Graphviz.
    # 'sphinx.ext.napoleon',              # Per supportare docstring Google/NumPy style.
]

sys.path.insert(0, os.path.abspath('../'))  # Modifica il percorso se necessario

templates_path = ['_templates']
exclude_patterns = []

inheritance_graph_attrs = dict(rankdir="TB", size='""')

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
