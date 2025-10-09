if not have_libtcg
   subdir_done()
endif

libtcg_sources = files(
  'libtcg.c',
  'dump_tinycode_instruction.c'
)

dl = cc.find_library('dl')
install_headers('../include/libtcg/libtcg_loader.h', subdir: 'qemu/libtcg')
libtcg_loader = shared_library('tcg-loader',
                               sources: 'libtcg_loader.c',
                               dependencies: dl,
                               install: true)
