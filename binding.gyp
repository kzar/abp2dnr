{
  "targets": [
    {
      "target_name": "isRegexSupported",
      "sources": [
        "lib/is_regex_supported.cc",
        "re2/re2/bitstate.cc",
        "re2/re2/compile.cc",
        "re2/re2/dfa.cc",
        "re2/re2/filtered_re2.cc",
        "re2/re2/mimics_pcre.cc",
        "re2/re2/nfa.cc",
        "re2/re2/onepass.cc",
        "re2/re2/parse.cc",
        "re2/re2/perl_groups.cc",
        "re2/re2/prefilter.cc",
        "re2/re2/prefilter_tree.cc",
        "re2/re2/prog.cc",
        "re2/re2/re2.cc",
        "re2/re2/regexp.cc",
        "re2/re2/set.cc",
        "re2/re2/simplify.cc",
        "re2/re2/stringpiece.cc",
        "re2/re2/tostring.cc",
        "re2/re2/unicode_casefold.cc",
        "re2/re2/unicode_groups.cc",
        "re2/util/pcre.cc",
        "re2/util/rune.cc",
        "re2/util/strutil.cc"
      ],
      "cflags": [
        "-Wno-cast-function-type",
        "-Wno-missing-field-initializers"
      ],
      "defines": [
        "NOMINMAX"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "re2"
      ],
    }
  ]
}