from PyInstaller.utils.hooks import copy_metadata

# in order for viv-utils to use pkg_resources to fetch
# the installed version of vivisect,
# we need to instruct pyinstaller to embed this metadata.
#
# so we set the pyinstaller.spec/hookspath to reference
#  the directory with this hook.
#
# this hook runs at analysis time and updates the embedded metadata.
#
# ref: https://github.com/pyinstaller/pyinstaller/issues/1713#issuecomment-162682084
datas = copy_metadata("vivisect")
