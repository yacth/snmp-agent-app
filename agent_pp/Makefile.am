  ############################################################################
  ## 
  ##  AGENT++ 4.0 - Makefile.am  
  ## 
  ##  Copyright (C) 2000-2013  Frank Fock and Jochen Katz (agentpp.com)
  ##  
  ##  Licensed under the Apache License, Version 2.0 (the "License");
  ##  you may not use this file except in compliance with the License.
  ##  You may obtain a copy of the License at
  ##  
  ##      http:/www.apache.org/licenses/LICENSE-2.0
  ##  
  ##  Unless required by applicable law or agreed to in writing, software
  ##  distributed under the License is distributed on an "AS IS" BASIS,
  ##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ##  See the License for the specific language governing permissions and
  ##  limitations under the License.
  ##  
  ##########################################################################*

if BUILD_EXAMPLES
example_SUBDIRS = examples tools
endif

if BUILD_AGENPRO
agenpro_SUBDIRS = agenpro
endif

if BUILD_AGENPRO_SIMAGENT
agenpro_SUBDIRS = agenpro
endif

AM_CPPFLAGS = -I$(top_srcdir)/include $(PTHREAD_CFLAGS) @CLIBFLAGS@
SUBDIRS = include src $(example_SUBDIRS) ${agenpro_SUBDIRS}
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = agent++-4.pc.in libagent.h LICENSE-2_0.txt FAQ CHANGES README.autoconf doc_config mibs \
             cmake_config.h.in cmake_libagent.h.in CMakeLists.txt cmake/modules/Findsnmp_pp.cmake

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = agent++-4.pc

library_includedir = $(includedir)
library_include_HEADERS= libagent.h
