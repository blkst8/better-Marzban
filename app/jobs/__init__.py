import glob
import importlib.util
import sys
from os.path import basename, dirname, join

modules = glob.glob(join(dirname(__file__), "*.py"))

for file in modules:
    name = basename(file).replace('.py', '')
    if name.startswith('_'):
        continue

    # Register under the package namespace BEFORE executing, so any later
    # `from app.jobs import <name>` returns THIS module instance — the same
    # one the scheduler holds. Without it, two instances of each job module
    # exist and their module state (locks, sightings, flags) diverges.
    spec = importlib.util.spec_from_file_location(f"{__name__}.{name}", file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
