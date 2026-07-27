# Copyright (c) 2019,2024,2025,2026 MariaDB Corporation
# Copyright (c) 2026 lefred (Frédéric Descamps)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335 USA

FIND_PATH(CLAMAV_INCLUDE_DIR clamav.h)
FIND_LIBRARY(CLAMAV_LIBRARY NAMES clamav)

IF(CLAMAV_INCLUDE_DIR AND CLAMAV_LIBRARY)
  INCLUDE_DIRECTORIES(${CLAMAV_INCLUDE_DIR})
  MYSQL_ADD_PLUGIN(viruscan viruscan.cc
                   RECOMPILE_FOR_EMBEDDED
                   MODULE_ONLY
                   LINK_LIBRARIES ${CLAMAV_LIBRARY})
ELSE()
  MESSAGE(STATUS "Not building viruscan: libclamav development files not found")
ENDIF()
