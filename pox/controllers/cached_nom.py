#!/usr/bin/env python
# Nom nom nom nom

# NOTE: python dicts are thread-safe, implicitly

class CachedNom:
  """
  Nom is cached on the client side. For non-mutating operations,
  Nom remains local to the cache. For mutating operations, writes through
  to the nom server, and server invalidates all other cached Noms
  """

  mutating_methods = ["__setitem__", "__delitem__", "clear", "pop", "popitem", "update"]

  def __init__(self, nom_server):
    # TODO: make nom more general. Perhaps a graph object, e.g., NetworkX?
    self.nom = {}
    self.nom_server = nom_server

  def nom(self):
    return self.nom

  def nom_server(self):
    return self.nom_server

  def __getattr__(self,name):
    """
    Don't inherit from dictionary, rather, delegate to our class variable.
    We do this by defining the __getattribute__ method, which is equivalent
    to ruby's method_missing method.
    """

    return_val = getattr(self.nom, name)

    if name in self.mutating_methods:
      """
       __getattr__ will return a method-wrapper object to the caller.
      We need to wrap this again to ensure that a call to
      nom_server.put() is made after the method-wrapper is called
      """
      nom_server = self.nom_server
      cached_nom = self
      def wrapper_wrapper(self, args):
        """
        Note that `self` is now a different reference.
        Also note that the variables `nom_server`, `nom` and
        `return_val` are bound within this context.
        """
        return_val(self, args)
        nom_server.put(cached_nom)
      return wrapper_wrapper

    return return_val


if __name__ == "__main__":
  class MockServer:
    def put(self,nom):
      print "received put call, nom:", nom

  server = MockServer()
  nom = CachedNom(server)

  print "[1] = 1"
  nom[1] = 1
  print "[1]"
  print nom[1]
  print "re-assign"
  nom = CachedNom(server)
  print nom
