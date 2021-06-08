#[
  Description: This is a new Nim module
  Author:
]#
import ../nimyara
import os
import strutils
import segfaults

type
  CALLBACK_ARGS = object
    file_path*: string
    current_count*: int


proc callback_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let rule = cast[ptr YR_RULE](message_data)
    cast[ptr CALLBACK_ARGS](user_data).current_count += 1
    echo "Detected: ", rule.identifier, " at: ", cast[ptr CALLBACK_ARGS](user_data).file_path
  return CALLBACK_CONTINUE


proc callback_scan_process(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let rule = cast[ptr YR_RULE](message_data)
    cast[ptr CALLBACK_ARGS](user_data).current_count += 1
    echo "Detected: ", rule.identifier, " pid: ", cast[ptr CALLBACK_ARGS](user_data).file_path
  return CALLBACK_CONTINUE


proc scanFile(scanner: ptr YR_SCANNER, fileName: string, user_data: ptr CALLBACK_ARGS, total, err: var int) =
  if not fileExists(fileName):
    return
  else:
    total += 1
    user_data.file_path = fileName
    let fileScanResult = yr_scanner_scan_file(scanner, fileName)
    if fileScanResult != ERROR_SUCCESS:
      err += 1


proc scanDir(scanner: ptr YR_SCANNER, dirName: string, user_data: ptr CALLBACK_ARGS, total, err: var int) =
  if not dirExists(dirName):
    return
  else:
    for path in walkDirRec(dirName):
      scanFile(scanner, path, user_data, total, err)


proc scanProcesses(scanner: ptr YR_SCANNER, user_data: ptr CALLBACK_ARGS, total, err: var int) =
  # FIXME callback error memory leak
  const
    folderPath = "/proc/"
  var pid: int
  for kind, path in walkDir(folderPath):
    pid = 0
    if kind == pcDir or kind == pcLinkToDir:
      try:
        pid = parseInt(path.split("/")[^1])
      except:
        continue
      if pid == 0:
        continue
      let scanProcResult = yr_scanner_scan_proc(scanner, cast[cint](pid))
      if scanProcResult != ERROR_SUCCESS:
        err += 1
      total += 1


proc createScan*(dbPath: string, scanMode: int, isFastScan: bool, fileOrDirName = ""): int =
  #[
    Scan mode:
      0. File
      1. Dir
      2. Processes
  ]#
  # TODO allow custom rules using yr_scanner_create
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
    scanner: ptr YR_SCANNER
    user_data = CALLBACK_ARGS(filePath: fileORDirName, current_count: 0)
    total_scan, err = 0
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE
    timeout = 1000000
    flags = 0

  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return -1

  # LOAD DB FROM COMPILED DB. (yr_scanner_create is for text file rules so we don't use it)
  result = yr_rules_load(dbPath, addr(rules))

  case result
  of ERROR_COULD_NOT_OPEN_FILE:
    echo "Could not open db"
    return ERROR_COULD_NOT_OPEN_FILE
  of ERROR_INSUFFICIENT_MEMORY:
    echo "Memory error"
    return ERROR_INSUFFICIENT_MEMORY
  of ERROR_INVALID_FILE:
    echo "Invalid database file"
    return ERROR_INVALID_FILE
  of ERROR_CORRUPT_FILE:
    echo "Corrupted db"
    return ERROR_CORRUPT_FILE
  of ERROR_UNSUPPORTED_FILE_VERSION:
    echo "Unsupported Db version"
    return ERROR_UNSUPPORTED_FILE_VERSION
  else:
    discard

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))

  # INIT SCANNER
  result = yr_scanner_create(rules, addr(scanner))

  yr_scanner_set_flags(scanner, cast[cint](flags))
  yr_scanner_set_timeout(scanner, cast[cint](timeout))

  if result != ERROR_SUCCESS:
    echo "create_scanner_error"
    return -7

  if scanMode == 1:
    yr_scanner_set_callback(scanner, callback_scan, addr(user_data))
    scanDir(scanner, fileOrDirName, addr(user_data), total_scan, err)
  elif scanMode == 0:
    yr_scanner_set_callback(scanner, callback_scan, addr(user_data))
    scanFile(scanner, fileOrDirName, addr(user_data), total_scan, err)
  elif scanMode == 2:
    yr_scanner_set_callback(scanner, callback_scan_process, addr(user_data))
    scanProcesses(scanner, addr(user_data), total_scan, err)
  echo "Total: ", total_scan, " [Scanned: ", total_scan - err, " Err: ", err, "]"
  echo "Infected: ", user_data.current_count
  if scanner != nil:
    yr_scanner_destroy(scanner)
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()

discard createScan("rule.db", 0, false, "testsig")
