#@author capa
#@category Analysis
#@menupath Tools.Run capa analysis

program = currentProgram

print("PyGhidra OK")
print("Program:", program.getName())
print("Functions:",
      program.getFunctionManager().getFunctionCount())