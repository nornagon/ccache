#include "Context.hpp"
#include "Logging.hpp"
#include "assertions.hpp"
#include "emcc.hpp"

// The following Emscripten environment variables should be keyed into the common cache hash (can affect C++ preprocessing, compilation, and/or compilation stdout output message)
static const char* emcc_env_vars[] = {
  "EMMAKEN_CFLAGS",             // affects preprocessor, compilation, and stdout/stderr output
  // "EMMAKEN_COMPILER",        // affects preprocessor, compilation, and stdout/stderr output, but deprecated in Emscripten, so will disable ccache if enabled (see below).
  // "EMMAKEN_JUST_CONFIGURE",  // affects preprocessor, compilation, and stdout/stderr output. Handled specially below.
  "EMMAKEN_NO_SDK",             // affects preprocessor, compilation, and stdout/stderr output
  // "EMCC_AUTODEBUG",          // affects stdout/stderr, internal debugging tool. Will disable ccache if enabled (see below)
  "EMCC_CFLAGS",                // affects preprocessor, compilation, and stdout/stderr output
  // "EMCC_CORES",              // would affect stdout/stderr output if EMCC_DEBUG is also enabled, but since EMCC_DEBUG disables ccache, this can be ignored altogether.
  // "EMCC_DEBUG",              // affects stdout/stderr output. Will disable ccache
  // "EMCC_DEBUG_SAVE",         // affects stdout/stderr output. Will disable ccache
  // "EMCC_FORCE_STDLIBS",      // affects link stage behavior only, so can be ignored by ccache.
  // "EMCC_ONLY_FORCED_STDLIBS" // affects link stage behavior only, so can be ignored by ccache.
  "EM_LLVM_ROOT",               // affects preprocessor, compilation, and stdout/stderr output
  "EMCC_LOCAL_PORTS",           // affects preprocessor, compilation, and stdout/stderr output
  // "EMCC_STDERR_FILE"         // affects link stage behavior only, so can be ignored by ccache.
  // "EMCC_CLOSURE_ARGS"        // affects link stage behavior only, so can be ignored by ccache.
  // "EMCC_STRICT"              // affects preprocessor, compilation, and stdout/stderr output. Handled specially, since it interacts with the -s STRICT=0/1 setting.

  // "EMCC_SKIP_SANITY_CHECK",  // can affect stdout/stderr output, but ignored since only happens if config is bad
  // "EM_IGNORE_SANITY",        // can affect stdout/stderr output, but ignored since only happens if config is bad

  // "EM_CACHE"                 // affects preprocessor, compilation, and stdout/stderr output. Handled specially, since it interacts with the --cache=<path> setting.
  // "EM_CONFIG"                // affects preprocessor, compilation, and stdout/stderr output. Handled specially, since it interacts with the --em-config=<path> setting.
  0
};

const char** get_emcc_preprocessor_affecting_env_vars()
{
  return emcc_env_vars;
}

static const char* emcc_too_hard_env_vars[] = {
  "EMMAKEN_COMPILER", // -> unsupported_compiler_option
  "EMCC_AUTODEBUG",  // -> unsupported_compiler_option
  "EMCC_DEBUG",      // -> unsupported_compiler_option
  "EMCC_DEBUG_SAVE", // -> unsupported_compiler_option
  // EMMAKEN_JUST_CONFIGURE // -> autoconf_test
  0
};

static const char *read_param_from_cmdline(const Args& args, std::string param)
{
  std::string paramEq = param + '=';

  for (size_t i = 1; i < args.size(); i++) {
    if (args[i] == param) {
      if (i + 1 >= args.size()) {
        return 0;
      }
      return args[i + 1].c_str();
    }

#define starts_with(str, substr) (!strncmp((str), (substr), strlen((substr))))
    if (starts_with(args[i].c_str(), paramEq.c_str())) {
      return args[i].c_str() + paramEq.length();
    }
  }
  return 0;
}

static std::string find_em_config_filename(const Args& args)
{
  const char* em_config = read_param_from_cmdline(args, "--em-config");
  if (em_config) return em_config;
  return getenv("EM_CONFIG");
}

static std::string
read_file_to_string(const char* filename)
{
  FILE* config_file = fopen(filename, "r");
  if (!config_file) {
    return std::string();
  }
  fseek(config_file, 0, SEEK_END);
  int file_size = (int)ftell(config_file);
  if (file_size <= 0) {
    fclose(config_file);
    return std::string();
  }
  fseek(config_file, 0, SEEK_SET);
  char* buf = new char[(size_t)file_size + 1];
  buf[file_size] = '\0';
  size_t num_read = fread(buf, 1, file_size, config_file);
  buf[num_read] = '\0';
  fclose(config_file);
  std::string s = buf;
  delete[] buf;
  return s;
}

static std::string find_em_cache_directory(const Context &ctx)
{
  // 1. read cache setting from command line
  const char* cache = read_param_from_cmdline(ctx.orig_args, "--cache");
  if (cache) return cache;

  // 2. read cache from environment variable
  cache = getenv("EM_CACHE");
  if (cache) return cache;

  // 3. read cache from Emscripten config file
  std::string em_config_contents =
    read_file_to_string(ctx.emcc_context.em_config_filename.c_str());
  if (em_config_contents.empty()) {
    return std::string();
  }

  std::string cache_directory;
  const char* pos = em_config_contents.c_str();
  while (pos = strstr(pos, "CACHE")) {
    if (!(pos == em_config_contents.c_str() || pos[-1] == ' ' || pos[-1] == '\t'
          || pos[-1] == '\n')) {
      ++pos; // This is a substring of another variable, skip to next
      continue;
    }
    pos += strlen("CACHE");
    while (*pos == ' ') ++pos; // Consume whitespace
    if (*pos == '=') {
      ++pos;
      while (*pos == ' ') ++pos; // Consume whitespace

      if (*pos == '"' || *pos == '\'') { // Expect starting quote
        const char* end = pos + 1;
        // Find matching ending quote (" or ')
        while (*end && *end != '\n' && (*end != *pos || end[-1] == '\\')) {
          ++end;
        }

        if (*end == *pos) {
          cache_directory = std::string(pos + 1, end);
        }
        pos = end;
      }
    }
  }
  return cache_directory;
}

std::string trim_string(const char *start, const char *end)
{
  while (start < end && *start <= 0x20)
    ++start;
  while (end > start && end[-1] <= 0x20)
    --end;
  return std::string(start, end);
}

std::string
git_read_repository_hash(const std::string& repository_path)
{
  PROCESS_INFORMATION pi;
  memset(&pi, 0x00, sizeof(pi));

  STARTUPINFO si;
  memset(&si, 0x00, sizeof(si));
  si.dwFlags = STARTF_USESTDHANDLES;

  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0x00, sizeof(sa));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  HANDLE childStdoutReadPipe = NULL;
  if (!CreatePipe(&childStdoutReadPipe, &si.hStdOutput, &sa, 0)) {
    exit(1);
  }
  SetHandleInformation(childStdoutReadPipe, HANDLE_FLAG_INHERIT, 0);

  char cmd_line[] = "git rev-parse HEAD";
  BOOL success = CreateProcess(nullptr,
                               cmd_line,
                               nullptr,
                               nullptr,
                               TRUE,
                               0,
                               nullptr,
                               repository_path.c_str(),
                               &si,
                               &pi);
  if (!success) {
    exit(2);
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exitcode;
  GetExitCodeProcess(pi.hProcess, &exitcode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  if (exitcode) {
    exit(exitcode);
  }

  char result[256] = {};
  DWORD nb = 0;
  success = ReadFile(childStdoutReadPipe, result, sizeof(result), &nb, 0);
  CloseHandle(childStdoutReadPipe);
  CloseHandle(si.hStdOutput);
  if (!success) {
    exit(3);
  }
  return trim_string(result, result + nb);
}

#ifdef _WIN32
#  define PATH_DELIMITER '\\'
#else
#  define PATH_DELIMITER '/'
#endif

std::string
get_directory_part(const std::string& absolute_path)
{
  int i = absolute_path.length() - 1;
  while (i > 0) {
    if (absolute_path[i] == PATH_DELIMITER)
      return absolute_path.substr(
        0, i + 1); // Include the path delimiter character
    --i;
  }
  return std::string();
}

nonstd::optional<Statistic>
read_emcc_context(Context& ctx)
{
  // Look out for environment variables that should disable ccache
  for (int i = 0; emcc_too_hard_env_vars[i]; ++i) {
    if (getenv(emcc_too_hard_env_vars[i])) {
      LOG("Environment variable {} is present, so disabling ccache",
          emcc_too_hard_env_vars[i]);
      return Statistic::unsupported_compiler_option;
    }
  }

  // If we are doing autoconf operation, also disable ccache
  if (getenv("EMMAKEN_JUST_CONFIGURE")) {
    return Statistic::autoconf_test;
  }

  // Read EM_CONFIG from cmdline or env. var
  ctx.emcc_context.em_config_filename = find_em_config_filename(ctx.orig_args);
  if (ctx.emcc_context.em_config_filename.empty()) {
    return Statistic::compiler_check_failed;
  }
  LOG("EM_CONFIG: {}", ctx.emcc_context.em_config_filename);

  // Read EM_CACHE from cmdline, env. var or config
  ctx.emcc_context.em_cache_filename = find_em_cache_directory(ctx);
  if (ctx.emcc_context.em_cache_filename.empty()) {
    return Statistic::compiler_check_failed;
  }
  LOG("EM_CACHE: {}", ctx.emcc_context.em_cache_filename);

  // Read Emscripten compiler version (either git hash or version number)
  std::string compiler_directory = get_directory_part(ctx.orig_args[0]);
  if (Stat::stat(compiler_directory + ".git").is_directory()) {
    ctx.emcc_context.compiler_version = git_read_repository_hash(compiler_directory);
  } else {
    ctx.emcc_context.compiler_version = read_file_to_string(
      (compiler_directory + "emscripten-version.txt").c_str());
    ctx.emcc_context.compiler_version =
      trim_string(ctx.emcc_context.compiler_version.c_str(),
                  ctx.emcc_context.compiler_version.c_str()
                    + ctx.emcc_context.compiler_version.length());
  }

  return nonstd::nullopt;
}

void
hash_emcc_common_state(const Context& ctx,
                       const Args& /*args*/,
                       Hash& hash,
                       const ArgsInfo& /*args_info*/)
{
  // Hash the environment variables that can affect both preprocessing and
  // compilation.
  for (int i = 0; emcc_env_vars[i]; ++i) {
    const char* value = getenv(emcc_env_vars[i]);
    if (value) {
      hash.hash_delimiter(emcc_env_vars[i]);
      hash.hash(value);
    }
  }

  // Hash EM_CONFIG file last modification time so that if config is changed, the cache is reset.
  hash.hash_delimiter("EM_CONFIG");
  hash.hash(Stat::stat(ctx.emcc_context.em_config_filename, Stat::OnError::throw_error).mtime());

  // Hash the Emscripten compiler version, so that if a new compiler is updated (in same directory),
  // the cache is reset.
  hash.hash_delimiter("EMCC_VER");
  hash.hash(ctx.emcc_context.compiler_version);

  // Hash EM_CACHE sysroot generation timestamp file last modification time, so that if something
  // changes in the sysroot cache, the cache is reset.
  hash.hash_delimiter("EM_CACHE");
  hash.hash(Stat::stat(ctx.emcc_context.em_cache_filename, Stat::OnError::throw_error).mtime());
}
