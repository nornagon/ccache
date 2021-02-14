#pragma once

#include "Args.hpp"
#include "ArgsInfo.hpp"
#include "Hash.hpp"
#include "NonCopyable.hpp"
#include "Statistic.hpp"
#include "argprocessing.hpp"
#include "third_party/nonstd/optional.hpp"

class Context;

class EmccContext : NonCopyable
{
public:
  std::string em_config_filename;
  std::string compiler_version;
  bool strict;

  // Currently we always only link in the system files at final link step, so
  // applications can/should not be linking in system lib files at compilation
  // stage, so if content in the cache changes, it won't matter.
#if 0
  std::string em_cache_timestamp_filename;
#endif
};

nonstd::optional<Statistic> read_emcc_context(Context& ctx);

nonstd::optional<Statistic> process_emcc_arg(Context& ctx,
                                             Args& args,
                                             size_t& args_index,
                                             ArgumentProcessingState& state);

void hash_emcc_common_state(const Context& ctx,
                          const Args& args,
                          Hash& hash,
                          const ArgsInfo& args_info);

