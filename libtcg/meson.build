libtcg_ss = ss.source_set()

libtcg_ss.add(files(
  'libtcg.c',
  'dump_tinycode_instruction.c'
))

dl = cc.find_library('dl')
install_headers('../include/libtcg/libtcg_loader.h', subdir: 'qemu/libtcg')
libtcg_loader = shared_library('tcg-loader',
                               sources: 'libtcg_loader.c',
                               dependencies: dl,
                               install: true)


specific_ss.add_all(when: 'CONFIG_LIBTCG', if_true: libtcg_ss)
