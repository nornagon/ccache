/*
* Emscripten support for ccache.
* 
* Emscripten is implemented as two compiler executables "emcc" and "em++", with accompanied .bat file launchers on Windows.
* 
* The compiler is for the most parts a GCC/Clang compatible, with same compile time flags, that are passed directly to Clang, which Emscripten uses as a backend.
* The set of link time flags differs a lot though, but fortunately ccache does not need to care about those.
* 
* Special Emscripten unique flags that need extra logic to handle:
* 
* --default-obj-ext <.ext> (affects output artifact filename)
* --cache <path>           (specifies cache directory, interacts with EM_CONFIG file, and EM_CONFIG env. var)
* --em-config <path>       (specifies config file, interacts with EM_CONFIG env. var)
* -s STRICT[=0/1]          (specifies compilation mode, interacts with EMCC_STRICT env. var)
* 
* See also the set of environment variables that affect Emscripten compilation output below (emcc_env_vars array)
* 
* Emscripten command line flags that affect preprocessor output:
*
* -pthread                    (injects -D__EMSCRIPTEN_PTHREADS__ to compiled code)
* -s USE_PTHREADS[=0/1]       (injects -D__EMSCRIPTEN_PTHREADS__ to compiled code)
* -s EMSCRIPTEN_TRACING[=0/1] (injects -D__EMSCRIPTEN_TRACING__ to compiled code)
* -s STRICT[=0/1]             (injects -DEMSCRIPTEN to compiled code)
* -s STB_IMAGE[=0/1]          (injects -DSTB_IMAGE_IMPLEMENTATION to compiled code)
* 
* Emscripten unique compile time flags that affect compilation output (but not preprocessor):
* 
* --llvm-opts <level>
* -s MEMORY64[=0/1]
* -s DISABLE_EXCEPTION_CATCHING[=0/1]
* -s EXCEPTION_CATCHING_ALLOWED[=0/1]
* -s RELOCATABLE[=0/1]
* -s MAIN_MODULE[=0/1]
* -s SIDE_MODULE[=0/1]
* -s DEFAULT_TO_CXX[=0/1]
* 
* General (non compile time) flags that should just cause ccache to disable itself to avoid any complications:
* 
* --check
* --clear-cache
* --clear-ports
* --show-ports
* --cflags
* 
* Emscripten unique compile time flags that do not affect compilation output, but they do affect stdout results (so ccache should also key on these):
* 
* -v
* -Wwarn-absolute-paths
* --valid-abspath path
* -s VERBOSE[=0/1]
*
* Apart from the -s flags listed above, Emscripten has a lot of other -s FOO settings, but they are all link time only settings (so ccache can ignore those).
* The ccache support implementation here does not however treat those specially, but instead the cache *is* keyed on even the -s flags that
* do not affect compilation. The rationale for this is that:
*  - developers do not generally pass any of the link time -s flags at compile time anyway,
*  - if they do, the accident is benign (one gets a bit excess caching)
*  - if a new -s flag is added that does affect compilation (or one was accidentally missed by a bug), it will not need to be added here, but will automatically be recognized
*/
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

static const char *read_emcc_s_param_from_cmdline(const Args& args, std::string param)
{
  std::string paramEq = param + '=';
  std::string paramSEq = "-s" + param + '=';

  for (size_t i = 1; i < args.size(); i++) {
    if (args[i] == "-s") {
      if (i + 1 >= args.size()) {
        return 0;
      }
      // "-s FOO=<value>"
      if (starts_with(args[i + 1].c_str(), paramEq.c_str())) {
        return args[i + 1].c_str() + paramEq.length();
      }
      // "-s FOO" produces an implicit true.
      if (args[i + 1] == param) {
        return "1";
      }
    }

    // "-sFOO=<value>"
    if (starts_with(args[i].c_str(), paramSEq.c_str())) {
      return args[i].c_str() + paramSEq.length();
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

static bool find_emcc_strict_value(const Args& args)
{
  const char* strict = read_emcc_s_param_from_cmdline(args, "STRICT");
  if (!strict) strict = getenv("EMCC_STRICT");
  if (!strict) return false;
  return !!strcmp(strict, "0");
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

#ifdef _WIN32
#  define DIR_SEPARATOR '\\'
#  define is_dir_separator(x) ((x) == '\\' || (x) == '/')
#else
#  define DIR_SEPARATOR '/'
#  define is_dir_separator(x) ((x) == '/')
#endif

#if 0
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
  while ((pos = strstr(pos, "CACHE"))) {
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
  // 4. If cache_directory is empty at this point, we are in a hard situation.
  // The cache will either be taken from 'cache' under emscripten root directory,
  // or from user home directory, if emscripten root directory is not writable,
  // or if FROZEN_CACHE is set. To be safe, return empty string, which will
  // cause ccache to be disabled at this point altogether.
  return cache_directory;
}
#endif

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
#ifdef _WIN32
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

#else

static std::string join_path(const std::string &lhs, const std::string &rhs)
{
  if (is_dir_separator(lhs[lhs.length() - 1]))
    return lhs + rhs;
  else
    return lhs + DIR_SEPARATOR + rhs;
}

#define die(e) do { fprintf(stderr, "%s\n", e); exit(EXIT_FAILURE); } while (0);

  int streams[2] = {};
  if (pipe(streams) == -1) {
    die("pipe failed!");
  }

  std::string git_dir = "--git-dir=" + join_path(repository_path, ".git");
  pid_t pid = fork();
  if (pid == -1) {
    die("fork failed!");
  }
  if (pid == 0) {
    dup2(streams[1], STDOUT_FILENO);
    close(streams[0]);
    close(streams[1]);
    execlp("git", "git", git_dir.c_str(), "rev-parse", "HEAD", (char*)0);
    die("execlp failed!");
  } else {
    close(streams[1]);
    char result[256] = {};
    int nb = read(streams[0], result, sizeof(result));
    if (nb < 20) // should be a hash, so 40 bytes at least.
      die("read failed!");
    wait(NULL);
    return trim_string(result, result + sizeof(result));
  }
#endif
}

std::string
get_directory_part(const std::string& absolute_path)
{
  int i = absolute_path.length() - 1;
  while (i > 0) {
    if (absolute_path[i] == DIR_SEPARATOR)
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

  // Currently we always only link in the system files at final link step, so
  // applications can/should not be linking in system lib files at compilation
  // stage, so if content in the cache changes, it won't matter.
#if 0
  // Read EM_CACHE from cmdline, env. var or config
  ctx.emcc_context.em_cache_timestamp_filename = find_em_cache_directory(ctx);
  if (ctx.emcc_context.em_cache_timestamp_filename.empty()) {
    return Statistic::compiler_check_failed;
  }

  ctx.emcc_context.em_cache_timestamp_filename = join_path(
    ctx.emcc_context.em_cache_timestamp_filename, "sysroot_install.stamp");
  LOG("EM_CACHE: {}", ctx.emcc_context.em_cache_timestamp_filename);
#endif

  // Read value of -s STRICT[=0/1]
  ctx.emcc_context.strict = find_emcc_strict_value(ctx.orig_args);

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

  // Read strict.

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

  // Hash the value of -s STRICT
  hash.hash_delimiter("EMCC_STRICT");
  hash.hash((int)ctx.emcc_context.strict);

  // Currently we always only link in the system files at final link step, so
  // applications can/should not be linking in system lib files at compilation stage, so
  // if content in the cache changes, it won't matter.
#if 0
  // Hash EM_CACHE sysroot generation timestamp file last modification time, so that if something
  // changes in the sysroot cache, the cache is reset.
  hash.hash_delimiter("EM_CACHE");
  hash.hash(Stat::stat(ctx.emcc_context.em_cache_timestamp_filename,
                       Stat::OnError::throw_error)
              .mtime());
#endif
}
