#init_shared.py
# Description:
# This file, init_shared.py, is responsible for initializing and providing access to shared data across different modules in the Ragnar project.
#
# Key functionalities include:
# - Importing the `SharedData` class from the `shared` module.
# - Creating an instance of `SharedData` named `shared_data` that holds common configuration, paths, and other resources.
# - Ensuring that all modules importing `shared_data` will have access to the same instance, promoting consistency and ease of data management throughout the project.

import os
import sys

# Pager mode: ensure bundled lib/ is on sys.path before any other imports.
# PagerRagnar.py also does this, but init_shared may be imported first by
# other modules (orchestrator, display, etc.) so we must handle it here too.
if os.environ.get('RAGNAR_PAGER_MODE') == '1':
    _lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
    if os.path.exists(_lib_path) and _lib_path not in sys.path:
        sys.path.insert(0, _lib_path)
    os.environ.setdefault('CRYPTOGRAPHY_OPENSSL_NO_LEGACY', '1')

from shared import SharedData

shared_data = SharedData()

# Add attributes to allow dynamic assignment without Pylance errors
# These are assigned at runtime in Ragnar.py and other modules
shared_data.ragnar_instance = None
shared_data.display_instance = None
