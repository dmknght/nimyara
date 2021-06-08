rule test_rule
{
  meta:
    description = "Test rule"
    author = "Nong Hoang Tu"
  strings:
    $s1 = "Something"
  condition:
    $s1
}