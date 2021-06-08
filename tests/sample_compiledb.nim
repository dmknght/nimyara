#[
  Description: This is a new Nim module
  Author:
]#
import .../nimyara
import os
import strutils


proc createDb*(src, dst: string) =
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
  let setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE
  if yr_initialize() != ERROR_SUCCESS:
    return
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(setting_max_string))
  if fileExists(src):
    discard yr_compiler_add_file(compiler, open(src), "Nim-yara-rules", src)
    discard yr_compiler_get_rules(compiler, addr(rules))
    discard yr_rules_save(rules, dst)
  else:
    for kind, path in walkDir(src):
      if kind == pcFile and path.endsWith(".yara"):
        discard yr_compiler_add_file(compiler, open(path), "Nim-yara-rules", path.split("/")[^1])
        discard yr_compiler_get_rules(compiler, addr(rules))
    discard yr_rules_save(rules, dst)
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()