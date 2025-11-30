# Vulnerable Parameter Detector (ParamSage)

Why this name?
ParamSage: “Parameter” + “Sage” (wise), implies it knows the risk of each parameter.

What it does?
Maps parameter names to commonly associated vulnerability types.

## Introduction
Some HTTP parameter names are more frequently associated with certain functionalities. For example, the parameter `?url=` usually contains a URL as its value and is therefore often susceptible to open redirect and SSRF attacks. ParamSage can process a list of URLs to identify such parameter names and the vulnerabilities typically linked to them. It is designed to assist web security testing by helping prioritize components for testing.

### Some points to keep in mind or might come handy while using ParamSage
- Input parameter names are treated case-insensitively (e.g., TO, to, and To are treated the same). Output preserves the original casing of parameters for input provided using pipe but not for input keywords (parameters) provided using cli options.
- `--onlykeywords` and `--addkeywords` are multually exclusive which means only one may be used per run. And either MUST appear last, after all other arguments.
- How `--addkeywords` and `--addkeywordsall` interact with `--removekeywordsall`.
    - When `--removekeywordsall` and `--addkeywordsall` are used together, `--addkeywordsall` takes precedence and re-adds the removed keywords globally (for all vuln types).
    - When `--removekeywordsall` and `--addkeywords` are used together, `--addkeywords` takes precedence and reassigns the removed keywords to the specified vuln types.
- How `--addkeywords` and `--addkeywordsall` interact with `--removekeywords`.
    - When `--removekeywords` and `--addkeywordsall` are used together, `--addkeywordsall` takes precedence and re-adds the removed keywords globally (for all vuln types).
    - When `--removekeywords` and `--addkeywords` are used together, `--addkeywords` takes precedence. Any vuln type with their corresponding keywords added using `--addkeywords` will be added regardless they are removed using `--removekeywords` or not.
- Incomplete option names are accepted. For example, `--nostr` is a valid shorthand for `--nostrict`. However, always use the full option name!

- Tip: When filtering output by vulnerability type: Since a single URL can be associated with multiple vuln types, avoid using 'grep -v' to exclude other types - it may even filter out URLs having the target vuln type.  Instead, use 'grep <vulntype>' to include what you want, even if other vuln types are also shown.
