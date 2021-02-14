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

#include "Args.hpp"
#include "Statistic.hpp"

#include "third_party/nonstd/optional.hpp"

class Context;

struct ProcessArgsResult
{
  ProcessArgsResult(Statistic error_);
  ProcessArgsResult(const Args& preprocessor_args_,
                    const Args& extra_args_to_hash_,
                    const Args& compiler_args_);

  // nullopt on success, otherwise the statistics counter that should be
  // incremented.
  nonstd::optional<Statistic> error;

  // Arguments (except -E) to send to the preprocessor.
  Args preprocessor_args;

  // Arguments not sent to the preprocessor but that should be part of the hash.
  Args extra_args_to_hash;

  // Arguments to send to the real compiler.
  Args compiler_args;
};

enum class ColorDiagnostics : int8_t { never, automatic, always };

struct ArgumentProcessingState
{
  bool found_c_opt = false;
  bool found_dc_opt = false;
  bool found_S_opt = false;
  bool found_pch = false;
  bool found_fpch_preprocess = false;
  ColorDiagnostics color_diagnostics = ColorDiagnostics::automatic;
  bool found_directives_only = false;
  bool found_rewrite_includes = false;

  std::string explicit_language;    // As specified with -x.
  std::string input_charset_option; // -finput-charset=...

  // Is the dependency makefile name overridden with -MF?
  bool dependency_filename_specified = false;

  // Is the dependency target name implicitly specified using
  // DEPENDENCIES_OUTPUT or SUNPRO_DEPENDENCIES?
  bool dependency_implicit_target_specified = false;

  // Is the compiler being asked to output debug info on level 3?
  bool generating_debuginfo_level_3 = false;

  // common_args contains all original arguments except:
  // * those that never should be passed to the preprocessor,
  // * those that only should be passed to the preprocessor (if run_second_cpp
  //   is false), and
  // * dependency options (like -MD and friends).
  Args common_args;

  // cpp_args contains arguments that were not added to common_args, i.e. those
  // that should only be passed to the preprocessor if run_second_cpp is false.
  // If run_second_cpp is true, they will be passed to the compiler as well.
  Args cpp_args;

  // dep_args contains dependency options like -MD. They are only passed to the
  // preprocessor, never to the compiler.
  Args dep_args;

  // compiler_only_args contains arguments that should only be passed to the
  // compiler, not the preprocessor.
  Args compiler_only_args;

  // compiler_only_args_no_hash contains arguments that should only be passed to
  // the compiler, not the preprocessor, and that also should not be part of the
  // hash identifying the result.
  Args compiler_only_args_no_hash;
};

inline ProcessArgsResult::ProcessArgsResult(Statistic error_) : error(error_)
{
}

inline ProcessArgsResult::ProcessArgsResult(const Args& preprocessor_args_,
                                            const Args& extra_args_to_hash_,
                                            const Args& compiler_args_)
  : preprocessor_args(preprocessor_args_),
    extra_args_to_hash(extra_args_to_hash_),
    compiler_args(compiler_args_)
{
}

ProcessArgsResult process_args(Context& ctx);
