"""utils package — shared utilities for the VPN config pipeline.

Deliberately re-exports nothing. An eager ``from utils.x import Y`` here runs
that module for *every* ``utils.*`` import, so a module that needs only
``ConfigTagger`` would still pull PyGithub into the process and a venv without
it could not even collect the tests. Import from the defining module:

    from utils.config_tagger import ConfigTagger
"""
