llvm_dep  = dependency('llvm', modules : ['support'])
opt       = find_program(llvm_dep.get_variable(configtool: 'bindir') / 'opt')
clang     = find_program(llvm_dep.get_variable(configtool: 'bindir') / 'clang')
llvm_link = find_program(llvm_dep.get_variable(configtool: 'bindir') / 'llvm-link')

to_ll = files('to_ll.py')
