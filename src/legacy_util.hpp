// Copyright (C) 2020 Joel Rosdahl and other contributors
//
// See doc/AUTHORS.adoc for a complete list of contributors.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 51
// Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#pragma once

#include "system.hpp"

#include <string>

void fatal(const char* format, ...) ATTR_FORMAT(printf, 1, 2) ATTR_NORETURN;

const char* get_hostname();
void x_setenv(const char* name, const char* value);
void x_unsetenv(const char* name);
#ifndef HAVE_LOCALTIME_R
struct tm* localtime_r(const time_t* timep, struct tm* result);
#endif
const char* get_home_directory();
bool is_full_path(const char* path);
void update_mtime(const char* path);
void x_exit(int status) ATTR_NORETURN;
int x_rename(const char* oldpath, const char* newpath);
void set_cloexec_flag(int fd);
double time_seconds();
