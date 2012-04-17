import select

class EpollSelect(object):
  """ a class that implements select.select() type behavior on top of epoll.
      Necessary, because select() only works on FD_SETSIZE (typically 1024) fd's at a time
  """

  def __init__(self):
    self.epoll = select.epoll()
    self.fd_to_obj = {}
    self.registered = {}
    self.lastrl = []
    self.lastrl_set = set()
    self.lastwl = []
    self.lastwl_set = set()

  def select(self, rl, wl, xl, timeout=0):
    """ emulate the select semantics on top of _epoll.
        Note this tries to emulate the behavior of select.select() 
          - you can pass a raw fd, or an object that answers to #fileno().
          - will return the object that belongs to the fd
    """

    # a map of fd's that need to be modified. 
    # fd -> flag to be set (0 for unregister fd)
    modify={}

    def modify_table(current_obj_list, old_fd_set, op):
      """ add operations to modify the registered fd's for operation / epoll mask 'op'
          Returns the old_fd_set you should pass in next time
          Also updates the fd_to_obj map.
          Yes, this is ugly. """
      current_fd_set = set()
      for obj in current_obj_list:
        # iterate through current_obj_list, udpate fd to obj mapping, and create set of fds
        fd = obj.fileno() if hasattr(obj, "fileno") else obj
        self.fd_to_obj[fd] = obj
        current_fd_set.add(fd)

      # new fds to register (for this op)
      new = current_fd_set - old_fd_set
      for fd in new:
        if not fd in modify:
          modify[fd] = self.registered[fd] if fd in self.registered else 0
        modify[fd] |= op
      # fd's to remove (at least for this op)
      expired = old_fd_set - current_fd_set
      for fd in expired:
        if not fd in modify:
          modify[fd] = self.registered[fd] if fd in self.registered else 0
        modify[fd] &= ~op

      return current_fd_set

    # optimization assumptions
    # rl is large and rarely changes
    if rl != self.lastrl:
      self.lastrl_set = modify_table(rl, self.lastrl_set, select.EPOLLIN|select.EPOLLPRI)
      self.lastrl = rl

    if wl != self.lastwl:
      self.lastwl_set = modify_table(wl, self.lastwl_set, select.EPOLLOUT)
      self.lastwl = wl

    # ignore XL. Tough luck, epoll /always/ checks for error conditions
    # you should, anyway

    # now execute the modify ops on the epoll object
    for (fd, mask) in modify.iteritems():
      if fd in self.registered:
        if mask == 0:
          self.epoll.unregister(fd)
          del self.registered[fd]
        else:
          self.epoll.modify(fd, mask)
          self.registered[fd] = mask
      else:
        if mask == 0:
          raise AssertionError("This should never happen - a new fd was scheduled for modification but neither for read nor write_")
        else:
          self.epoll.register(fd, mask)
          self.registered[fd] = mask

    # now for the real beef
    events = self.epoll.poll(timeout)

    # convert the events list of (fd, event) tuple to the three lists expected by select users
    retrl = []
    retwl = []
    retxl = []
    for (fd, event) in events:
      if event & (select.EPOLLIN|select.EPOLLPRI|select.EPOLLRDNORM|select.EPOLLRDBAND):
        retrl.append(self.fd_to_obj[fd])
      if event & (select.EPOLLOUT|select.EPOLLWRNORM|select.EPOLLWRBAND):
        retwl.append(self.fd_to_obj[fd])
      if event & (select.EPOLLERR|select.EPOLLHUP):
        retxl.append(self.fd_to_obj[fd])

    return (retrl, retwl, retxl)

  def close(self):
    self.epoll.close()
