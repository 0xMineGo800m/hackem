#!/usr/bin/python3

import angr
import sys

def main(argv):
  path_to_binary = "./hashpretence"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    #Successful print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'SUCCESS' in stdout_output

  def should_abort(state):
    #Avoid this print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'FAILED' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    for byte in simulation.found[0].posix.dumps(0):
        print(hex(byte), end=', ')
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)