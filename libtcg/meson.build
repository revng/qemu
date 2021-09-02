libtcg_ss = ss.source_set()

libtcg_ss.add(files(
  'libtcg.c',
  'dump_tinycode_instruction.c'
))

specific_ss.add_all(when: 'CONFIG_LIBTCG', if_true: libtcg_ss)
