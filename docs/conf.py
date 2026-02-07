# Configuration file for the Sphinx documentation builder.
# http://www.sphinx-doc.org/en/stable/config

# -- Path setup --------------------------------------------------------------
import sys
import subprocess
from datetime import datetime
from pathlib import Path

docs_dir = Path(__file__).resolve().parent  # docs/
pardir = docs_dir.parent  # peat/
sys.path.insert(0, str(pardir))
sys.setrecursionlimit(1500)


def _clean_read(pth: Path) -> list:
    return [x.strip() for x in pth.read_text().splitlines() if x]


def get_git_version():
    try:
        # Run the git command to get the latest tag
        return subprocess.check_output(["git", "describe", "--tags"], encoding="utf-8").strip()
    except Exception:
        # Handle errors (e.g., if git is not available or no tags exist)
        return "dev"  # Default version if no tags are found


# -- Extensions --------------------------------------------------------------
from recommonmark.transform import AutoStructify

extensions = [
    "sphinx.ext.napoleon",  # Google-style docstrings (built-in)
    "sphinx.ext.viewcode",  # Links to source code (built-in)
    "sphinx.ext.autodoc",  # Auto-generated source code API docs (built-in)
    "sphinx.ext.todo",  # Blocks of TODOs for use in module documentation
    "sphinx.ext.intersphinx",  # External code documentation linkages
    # NOTE: sphinx.ext.napoleon MUST be loaded before sphinx_autodoc_typehints
    "sphinx_autodoc_typehints",  # Use Python type annotations for types in docs
    "sphinx_automodapi.automodapi",  # NOTE: requires Graphviz
    "sphinx_copybutton",  # Adds a copy to clipboard button to code blocks
    "sphinx_argparse_cli",  # Document CLI arguments
    "recommonmark",  # Markdown file parsing
    "sphinxcontrib.autodoc_pydantic",
]

autodoc_pydantic_model_show_config_summary = False
autodoc_pydantic_model_show_config_member = False
autodoc_pydantic_model_signature_prefix = " "
autodoc_pydantic_field_show_default = False
autodoc_pydantic_field_signature_prefix = " "
autodoc_pydantic_model_show_json = True
# NOTE (cegoes, 06/03/2022 and 06/16/2023)
# autodoc_pydantic >= 1.7.0 errors out when "bysource" is used for list order
# Should be fixed in 1.9.0: https://github.com/mansenfranzen/autodoc_pydantic/issues/137
# autodoc_pydantic_model_summary_list_order = "bysource"


# -- Project metadata --------------------------------------------------------
project = "PEAT"
language = "en"
date = datetime.now().strftime("%m/%d/%Y")
copyright = f"2016 - {datetime.now().year}, Sandia National Laboratories"
author = "Sandia National Laboratories"
authors = sorted(_clean_read(Path(pardir, "AUTHORS")))
version = get_git_version()
release = version


# -- General configuration ---------------------------------------------------
# Markdown:
#   https://www.sphinx-doc.org/en/master/usage/markdown.html
#   https://github.com/readthedocs/recommonmark
source_suffix = [".rst", ".md"]
source_encoding = "utf-8"
needs_sphinx = "7.0.0"

# Add any paths that contain templates here, relative to this directory
templates_path = ["_templates"]

# The “master” document, contains the root toctree directive
master_doc = "index"
exclude_patterns = [
    "_build",
    "_built_docs",
    ".doctrees",
    "Thumbs.db",
    ".DS_Store",
    ".vscode",
    ".idea",
    ".vagrant",
]
todo_include_todos = False

# Code styles: https://pygments.org/docs/styles/
pygments_style = "colorful"

# Intersphinx mapping for external documentation
intersphinx_mapping = {
    # Latest version of the mapping can be pulled from python.org:
    # https://docs.python.org/3/objects.inv
    "python": ("https://docs.python.org/3", "python3-docs-inventory.inv")
}


# Make :manpage directive work on HTML output
# https://www.sphinx-doc.org/en/master/usage/configuration.html?#confval-manpages_url
manpages_url = "https://manpages.debian.org/{path}"


# Napoleon settings (lets us use Google-style docstrings)
# https://www.sphinx-doc.org/en/master/usage/extensions/napoleon.html
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_attr_annotations = True


# sphinx-autodoc-typehints settings
# https://github.com/agronholm/sphinx-autodoc-typehints
always_document_param_types = False


# autodoc
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html
autodoc_default_options = {
    "member-order": "bysource",
    "undoc-members": True,
    # Include docs from members even if they're not included in '__all__'
    "ignore-module-all": True,
}
add_module_names = False


# automodapi
# https://sphinx-automodapi.readthedocs.io/en/latest/
automodapi_toctreedirnm = "automodapi_tmp"

smartquotes_action = "qe"


# -- Output configurations  -------------------------------------------------

# Configuration for HTML output
#   https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output
# HTML theme: Furo (https://pradyunsg.me/furo/)
html_theme = "furo"
html_title = "PEAT documentation"
html_short_title = "PEAT"
html_favicon = "favicon.ico"
html_logo = "favicon.ico"
html_last_updated_fmt = ""
html_theme_options = {
    "top_of_page_buttons": ["view", "edit"],
    "source_repository": "https://github.com/sandialabs/PEAT/",
    "source_branch": "main",
    "source_directory": "docs/",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/sandialabs/PEAT",
            "html": """
                <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 16 16">
                    <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
            """,
            "class": "",
        },
    ],
}


# Build command line interface (CLI) manpage (e.g. "man peat.1")
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-manual-page-output
man_pages = [
    (
        "operate",  # operate.rst
        "peat",
        "Process Extraction and Analysis Tool",
        authors,
        1,
    ),
]
man_show_urls = True


# TODO: build PDF using rinohtype (https://github.com/brechtm/rinohtype)
# https://www.mos6581.org/rinohtype/master/sphinx.html#sphinx-builder
# rinoh_documents = [{
#     "doc": "index",
#     "target": "peat",  # PDF filename
#     # TODO: logo?
# }]


# Recommonmark settings (lets us use Markdown instead of reStructuredText)
# https://recommonmark.readthedocs.io/en/latest/auto_structify.html
# https://github.com/rtfd/recommonmark/blob/master/docs/conf.py
def setup(app):
    app.add_config_value(
        "recommonmark_config",
        {
            "enable_eval_rst": True,
            "enable_auto_toc_tree": False,
            "enable_math": False,
            "enable_inline_math": False,
            "known_url_schemes": ["http", "https", "mailto"],
        },
        True,
    )
    app.add_transform(AutoStructify)
