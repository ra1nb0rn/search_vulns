# """search_vulns - Search for known vulnerabilities in software."""

__version__ = "0.7.4"

# # Compatibility layer for submodules that use old import paths
# # This allows submodules to import using the old structure (e.g., "from modules.X import Y")
# # without modifying the submodules themselves
# import sys
# import types

# # Create a fake 'modules' package that points to search_vulns.modules
# # This makes imports like "from modules.cpe_search.X import Y" work
# if "modules" not in sys.modules:
#     # Import the actual modules package
#     from . import modules as _real_modules
    
#     # Create a fake 'modules' package object with __path__ so Python treats it as a package
#     _fake_modules = types.ModuleType("modules")
#     _fake_modules.__path__ = _real_modules.__path__
#     _fake_modules.__package__ = "modules"
    
#     # Copy all attributes from the real modules to the fake one
#     for attr in dir(_real_modules):
#         if not attr.startswith("_"):
#             try:
#                 setattr(_fake_modules, attr, getattr(_real_modules, attr))
#             except (AttributeError, TypeError):
#                 pass
    
#     # Register the fake modules package
#     sys.modules["modules"] = _fake_modules
    
#     # Register all submodules (like modules.cpe_search, modules.utils, etc.)
#     # This is needed so "from modules.cpe_search import X" works
#     import importlib
#     for submodule_name in dir(_real_modules):
#         if not submodule_name.startswith("_"):
#             try:
#                 submodule = getattr(_real_modules, submodule_name)
#                 if isinstance(submodule, types.ModuleType):
#                     submodule_path = f"modules.{submodule_name}"
#                     sys.modules[submodule_path] = submodule
                    
#                     # Also register nested submodules if they exist
#                     # (e.g., modules.cpe_search.cpe_search)
#                     if hasattr(submodule, "__path__"):
#                         for nested_name in dir(submodule):
#                             if not nested_name.startswith("_"):
#                                 try:
#                                     nested = getattr(submodule, nested_name)
#                                     if isinstance(nested, types.ModuleType):
#                                         nested_path = f"modules.{submodule_name}.{nested_name}"
#                                         sys.modules[nested_path] = nested
#                                 except (AttributeError, TypeError):
#                                     pass
#             except (AttributeError, TypeError):
#                 pass

# # Also create compatibility for root-level imports that submodules might use
# # Make 'cpe_version' and 'vulnerability' available at root level for submodules
# if "cpe_version" not in sys.modules:
#     from . import cpe_version
#     sys.modules["cpe_version"] = cpe_version

# if "vulnerability" not in sys.modules:
#     from . import vulnerability
#     sys.modules["vulnerability"] = vulnerability
