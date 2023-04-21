import os
import sys

from distutils.core import setup

if os.path.exists('MANIFEST'):
  os.remove('MANIFEST')

import install
#
#-----------------------------------------------------------------------------
def main():
  if sys.version_info[:2] < (3, 6):
    print("nstipgeolocate requires Python version 3.6.x or higher.")
    sys.exit(1)

  if sys.argv[-1] == 'setup.py':
    print("To install, run 'python3 setup.py install'")
    print()

  setup(
    name             = install.name,
    packages         = install.packages,
    package_data     = install.package_data,
    scripts          = install.scripts,
  )
#
#-----------------------------------------------------------------------------
if __name__ == "__main__":
  main()
