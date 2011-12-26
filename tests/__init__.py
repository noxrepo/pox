from pox.core import core
import __main__

log = core.getLogger("tests")

_first = True
_tests = []

def _up (e):
  log.info("Starting")
  for test in _tests:
    log.info("Test " + test)
    if __main__.doImport("tests." + test) is True:
      log.error("Test %s not found", test)
      return

def launch (**kw):
  __main__.cli = False # Disable CLI
  global _first
  if _first:
    core.addListenerByName("UpEvent", _up)
    _first = False
  for k in kw:
    if k not in _tests:
      _tests.append(k)

