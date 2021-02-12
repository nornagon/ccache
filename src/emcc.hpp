#pragma once

#include "Args.hpp"
#include "ArgsInfo.hpp"
#include "Hash.hpp"
#include "NonCopyable.hpp"
#include "Statistic.hpp"
#include "third_party/nonstd/optional.hpp"

class Context;

class EmccContext : NonCopyable
{
public:
  std::string em_config_filename;
  std::string em_cache_filename;
  std::string compiler_version;
  bool strict;
};

nonstd::optional<Statistic> read_emcc_context(Context& ctx);

void hash_emcc_common_state(const Context& ctx,
                          const Args& args,
                          Hash& hash,
                          const ArgsInfo& args_info);
