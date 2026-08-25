"""Single source of truth for the ecosystem version.

Lives in a plain module rather than __init__.py because this package tree
deliberately uses no __init__.py files (PEP 420 namespace packages). Everything
that needs the version imports it from here:

    from version import __version__
"""

__version__ = "1.2.2"
