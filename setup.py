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
                             'sharkPy/dissect/c_src/sharkPyPrint.c',
                             'sharkPy/dissect/c_src/sharkPy.c',
                             'sharkPy/dissect/c_src/capture_opts.c',
                             'sharkPy/dissect/c_src/sharkPy_capture_sync.c',
                             'sharkPy/dissect/c_src/capture-pcap-util.c',
                             'sharkPy/dissect/c_src/capture_ui_utils.c',
                             'sharkPy/dissect/c_src/extcap.c',
                             'sharkPy/dissect/c_src/extcap_parser.c',
                             'sharkPy/dissect/c_src/capture_ifinfo.c',
                             'sharkPy/dissect/c_src/capture-pcap-util-unix.c',
                             'sharkPy/dissect/c_src/util.c',
                             'sharkPy/dissect/c_src/sync_pipe_write.c'],
                    library_dirs=['sharkPy/dissect/64_bit_libs'],
                    libraries= ['wireshark',
                               'wsutil',
                               'wiretap',
                               'glib-2.0',
                               'pcap'],
                    include_dirs=['sharkPy/dissect/c_src',
                                  'sharkPy/dissect/c_src/wireshark-2.0.4',
                                  'sharkPy/dissect/c_src/wireshark-2.0.4/epan',
                                  'sharkPy/dissect/c_src/wireshark-2.0.4/wsutil',
                                  'sharkPy/dissect/c_src/wireshark-2.0.4/wiretap',
                                  'sharkPy/dissect/c_src/wireshark-2.0.4/capchild',
                                   glib_includes[0],
                                   glib_includes[1],
                                   'sharkPy/common/c_src'],)

wire_write_module = Extension('write',
                              sources=['sharkPy/write/c_src/write.c'],
                              library_dirs=['sharkPy/dissect/64_bit_libs'],
                              libraries= ['pcap'],
                              include_dirs=['sharkPy/write/c_src'],)

#Thank you stackoverflow
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

setupfiles = package_files('sharkPy')

setup(name='sharkPy',
      version='0.3Beta',
      description='Python module to dissect and access network packet data using Wireshark capabilities and native Python objects.',
      ext_modules=[file_dissect_module,wire_write_module],
      author='Mark Landriscina',
      packages=['sharkPy', 'sharkPy.dissect', 'sharkPy.write', 'sharkPy.utils', 'sharkPy.protocol_blender'],
      package_data={'sharkPy':setupfiles} )


