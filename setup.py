#!/usr/bin/python
from distutils.core import setup, Extension
import os
import site, commands


def pkgconf(*packages, **kw):
    cfgInfo = {'-I':'include_dirs', '-L': 'library_dirs', '-l': 'libraries'}
    for fld in commands.getoutput("pkg-config --libs --cflags %s" % ' '.join(packages)).split():
        kw.setdefault(cfgInfo.get(fld[:2]), []).append(fld[2:])
    return kw

glib_includes=pkgconf('glib-2.0')['include_dirs']


cdir=os.getcwd()
install_dir='sharkPy'

file_dissect_module = Extension('dissect',
                    sources=['sharkPy/dissect/c_src/cfile.c',
                             'sharkPy/dissect/c_src/frame_tvbuff.c',
                             'sharkPy/dissect/c_src/print.c',
                             'sharkPy/dissect/c_src/sharkPy.c'],
                    library_dirs=['sharkPy/dissect/64_bit_libs'],
                    libraries= ['wsutil',
                               'wiretap',
                               'wireshark',
                               'glib-2.0',
                               'pcap'],
                    include_dirs=['sharkPy/dissect/c_src',
                                  'sharkPy/dissect/c_src/wireshark-2.0.1',
                                  'sharkPy/dissect/c_src/wireshark-2.0.1/epan',
                                  'sharkPy/dissect/c_src/wireshark-2.0.1/wsutil',
                                  'sharkPy/dissect/c_src/wireshark-2.0.1/wiretap',
                                   glib_includes[0],
                                   glib_includes[1],
                                   'sharkPy/common/c_src'],
                    runtime_library_dirs=[install_dir+'/dissect/64_bit_libs', install_dir+'/dissect/64_bit_libs/plugins/1.8.10', site.getsitepackages()[0]])

wire_write_module = Extension('write',
                              sources=['sharkPy/write/c_src/common.c'],
                              library_dirs=['sharkPy/dissect/64_bit_libs'],
                              libraries= ['pcap'],
                              include_dirs=['sharkPy/write/c_src'],
                              runtime_library_dirs=[install_dir+'/dissect/64_bit_libs'])


setup(name='sharkPy',
      version='0.3Beta',
      description='Python module to dissect and access network packet data using Wireshark capabilities and native Python objects.',
      ext_modules=[file_dissect_module,wire_write_module,],
      author='Mark Landriscina',
      packages=['sharkPy', 'sharkPy.dissect', 'sharkPy.write'],
      package_dir={'sharkPy': 'sharkPy'},
      package_data={'':['dissect',
                        'dissect/64_bit_libs/*',
                        'dissect/64_bit_libs/plugins/*',
                        'dissect/64_bit_libs/plugins/1.8.10/*',
                        'dissect/c_src/*',
                        'dissect/c_src/wireshark-2.0.1/*',
                        'write/c_src/*',
                        'common',
                        'common/c_src/*']})

