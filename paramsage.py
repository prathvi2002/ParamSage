#!/usr/bin/python3

import sys
from urllib.parse import urlparse
import argparse
from collections import defaultdict
import argcomplete


# valid vulnerability types for cli arguments
valid_vulntype_names = ["fileinclusion", "openredirect", "ssrf", "sqli"]


def detect_paramters(url):
    """Wrapper function which returns a list of all parameter names in a URL, including those without assigned values (e.g., "page" in "?page" or "?page=")

    Definitions:
        excluding empty keys: it means ignoring parameters that have no name before the equals sign, such as in =value. (e.g. http://example.com/home?=value&page=2)

    Args:
        url (str): URL whose path-embedded and query parameter names to be extracted.

    Returns:
        tuple: 
            - (str) url provided.
            - (list) All parameter names from the URL (path-embedded and query), excluding empty keys.
    """

    # For each url parameter query or path-embedded find unfiltered characters using unfiltered_characters function.
    # url = "https://example.com/products;category=electronics;brand=;items;id=1;color=black?sort=price&order=&page"  # example testing URL
    parsed = urlparse(url)

    # Extract path-embedded parameter names
    path_param_names = [pair.split("=")[0] for pair in parsed.params.split(";") if pair]

    # Extract query parameter names (even if no value is assigned)
    query_param_names = [pair.split("=")[0] for pair in parsed.query.split("&") if pair]

    all_parameters = path_param_names + query_param_names

    # Removes empty string elements from all_parameters if any present, caused by parameters with no name before the equal sign such as "=value" in http://example.com/home?=value&page=2
    # filtered_parameters_list = [item for item in all_parameters if item != ""]
    filtered_parameters_list = []
    for item in all_parameters:
        # If the parameter name is not an empty string, add it to the filtered list
        if item != "":
            filtered_parameters_list.append(item)
        # # If the parameter name is empty (e.g., "=value"), log a debug message
        # else:
        #     debug_print(f"{GRAY}[~] URL has parameter value but not name{RESET}", newline=True)

    return (url, filtered_parameters_list)


#! Do not modify the if/elif else structure or split continuous if-statements in this function. Their current form is intentional and necessary for the correct behavior of this tool.
def param_map(parameters, custom_keywords=False, custom_keywords_all=False, additional_keywords=False, removing_keywords=False, removing_keywords_all=False, additional_keywords_all=False, show_default=False):
    """Maps parameter names to commonly associated vulnerability types.

    Args:
        parameters (list): A list of parameter names (strings).
        custom_keywords (dict [each key's value being list], bool, optional): If dict passed, only this keywords dictionary will be used and not the default keywords dictionary. Defaults to False.
        custom_keywords_all (list, bool, optional): If list passed, only this keywords will be used for all vuln types and not the default keywords in dictionary. Defaults to False.
        additional_keywords (dict [each key's value being list], bool, optional): If dict passed, this keywords dictionary will be used in addition to the already present keywords dictionary. Defaults to False.
        removing_keywords_all (list, bool, optional): If list passed, all the keywords in this list will be removed from all the vuln types keywords (risky parameters). Defaults to False.
        additional_keywords_all (list, bool, optional): If list passed, all the keywords in this list will be add to all the vuln types keywords (risky parameters). Defaults to False.

    Returns:
        dict: A dictionary mapping each vulnerability type (str) to a list of parameter names (list of str) that are potentially associated with that risk. Dict values (Lists) will be empty if no matches are found. The entire dictionary will be empty if no parameter matches any known vulnerability type.
    """
    # Lists of DEFAULT parameter keywords commonly associated with specific vulnerability types. #! All keywords must be in lowercase, as parameter names are normalized using .lower() during matching.
    file_inclusion_words1 = ['file','document','folder','root','path','pg','style','pdf','template','php_path','doc']  # source: https://github.com/bugcrowd/HUNT/blob/master/ZAP/scripts/passive/File%20Inclusion.py
    file_inclusion_words2 = ["page", "name", "cat", "dir", "action", "board", "download", "include", "inc", "locate", "show", "view", "content", "conf", "layout", "mod"]  # source: https://github.com/g0ldencybersec/sus_params/blob/main/gf-patterns/lfi.json
    file_inclusion_words_default = sorted(list(set(file_inclusion_words1 + file_inclusion_words2)))

    open_redirect_words1 = ["redirect_uri", "failed", "referer", "return_url", "redirect_url", "prejoin_data", "x-forwarded-host", "continue", "redir", "return_to", "origin", "redirect_to", "next", "host"]  # source: https://github.com/g0ldencybersec/sus_params/blob/main/gf-patterns/redirect.json
    open_redirect_words2 = ["dir", "show", "site", "view", "callback", "checkout", "checkout_url", "continue", "dest", "destination", "domain", "feed", "file_url", "folder_url", "forward", "from_url", "go", "goto", "image_url", "img_url", "load_url", "login_url", "navigation", "next", "next_page", "open", "out", "page_url", "redir", "redirect", "redirect_to", "redirect_uri", "redirect_url", "reference", "return", "return_path", "return_to", "returnTo", "return_url", "rurl", "target", "to", "uri", "url", "val", "validate", "window"]  # source: https://github.com/s0md3v/Parth/blob/master/parth/core/param_map.py
    open_redirect_words_default = sorted(list(set(open_redirect_words1 + open_redirect_words2)))

    # you can further expand this list by reading SSRF write-ups and noticing which paramters were vulnerable to SSRFs
    ssrf_words1 = ['dest','redirect','uri','path','continue','url','window','next','data','reference','site','html','val','validate','domain','callback','return','page','feed','host','port','to','out','view','dir','show','navigation','open']  # source: https://github.com/bugcrowd/HUNT/blob/master/ZAP/scripts/passive/SSRF.py
    ssrf_words2 = ["endpoint", "src", "ip", "start", "source", "template", "metadata", "image_host", "filename", "stop", "resturl"]  # source: https://github.com/g0ldencybersec/sus_params/blob/main/gf-patterns/ssrf.json
    ssrf_words3 = ["file", "document", "folder", "root", "pg", "style", "doc", "php_path", "exec", "execute", "load", "destination", "delete", "access", "dbg", "debug", "grant", "alter", "clone", "create", "enable", "disable", "make", "modify", "rename", "reset", "shell", "cfg", "img"]  # source: https://github.com/s0md3v/Parth/blob/master/parth/core/param_map.py
    ssrf_words4 = ["remote", "region", "proxy", "http", "img_url", "upload"]  # my own curated keywords
    ssrf_words_default = sorted(list(set(ssrf_words1 + ssrf_words2 + ssrf_words3 + ssrf_words4)))

    xss_words_default = ["onafterprint", "onafterscriptexecute", "onanimationcancel", "onanimationend", "onanimationiteration", "onanimationstart", "onauxclick", "onbeforecopy", "onbeforecut", "onbeforeinput", "onbeforepaste", "onbeforeprint", "onbeforescriptexecute", "onbeforetoggle", "onbeforeunload", "onbegin", "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick", "onclose", "oncommand", "oncontentvisibilityautostatechange", "oncontentvisibilityautostatechange(hidden)", "oncontextmenu", "oncopy", "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragexit", "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onend", "onended", "onerror", "onfocus", "onfocus(autofocus)", "onfocusin", "onfocusout", "onformdata", "onfullscreenchange", "ongesturechange", "ongestureend", "ongesturestart", "onhashchange", "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata", "onloadstart", "onmessage", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onmozfullscreenchange", "onpagehide", "onpagereveal", "onpageshow", "onpageswap", "onpaste", "onpause", "onplay", "onplaying", "onpointercancel", "onpointerdown", "onpointerenter", "onpointerleave", "onpointermove", "onpointerout", "onpointerover", "onpointerrawupdate", "onpointerup", "onpopstate", "onprogress", "onratechange", "onrepeat", "onreset", "onresize", "onscroll", "onscrollend", "onscrollsnapchange", "onscrollsnapchanging", "onsearch", "onsecuritypolicyviolation", "onseeked", "onseeking", "onselect", "onselectionchange", "onselectstart", "onshow", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle", "ontoggle(popover)", "ontouchcancel", "ontouchend", "ontouchmove", "ontouchstart", "ontransitioncancel", "ontransitionend", "ontransitionrun", "ontransitionstart", "onunhandledrejection", "onunload", "onvolumechange", "onwaiting", "onwaiting(loop)", "onwebkitanimationend", "onwebkitanimationiteration", "onwebkitanimationstart", "onwebkitfullscreenchange", "onwebkitmouseforcechanged", "onwebkitmouseforcedown", "onwebkitmouseforceup", "onwebkitmouseforcewillbegin", "onwebkitplaybacktargetavailabilitychanged", "onwebkitpresentationmodechanged", "onwebkittransitionend", "onwebkitwillrevealbottom", "onwheel"]  # source: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (events section)

    sqli_words1 = ['id','select','report','role','update','query','user','name','sort','where','search','params','process','row','view','table','from','sel','results','sleep','fetch','order','keyword','column','field','delete','string','number','filter']  # source: https://github.com/bugcrowd/HUNT/blob/master/ZAP/scripts/passive/SQLi.py
    sqli_words2 = ["process", "referer", "password", "pwd", "view", "sleep", "column", "log", "token", "sel", "select", "sort", "from", "search", "update", "pub_group_id", "row", "results", "role", "table", "multi_layer_map_list", "order", "filter", "user", "fetch", "limit", "keyword", "email", "query", "name", "where", "number", "phone_number", "delete", "report"]  # source: https://github.com/g0ldencybersec/sus_params/blob/main/gf-patterns/sqli.json
    sqli_words_default = sorted(list(set(sqli_words1 + sqli_words2)))


    if show_default is True:
        print(f"\nfileinclusion: [{' '.join(file_inclusion_words_default)}]")
        print(f"\nopenredirect: [{' '.join(open_redirect_words_default)}]")
        print(f"\nssrf: [{' '.join(ssrf_words_default)}]")
        print(f"\nxss: [{' '.join(xss_words_default)}]")
        print(f"\nsqli: [{' '.join(sqli_words_default)}]")
        sys.exit(0)


    # if custom only keywords (risky parameters) are provided to this function, then set keywords to this. (down side custom keywords will be passed to this param_map function when --onlykeywords flag with arguments will be used)
    if custom_keywords:
        debug_print(f"custom keyword on {custom_keywords}")
        # these if statments are to save us from "TypeError: argument of type 'NoneType' is not iterable" error
        if bool(custom_keywords.get("file_inclusion_words")) is False:
            custom_keywords["file_inclusion_words"] = []
        if bool(custom_keywords.get("open_redirect_words")) is False:
            custom_keywords["open_redirect_words"] = []
        if bool(custom_keywords.get("ssrf_words")) is False:
            custom_keywords["ssrf_words"] = []
        if bool(custom_keywords.get("xss_words")) is False:
            custom_keywords["xss_words"] = []
        if bool(custom_keywords.get("sqli_words")) is False:
            custom_keywords["sqli_words"] = []
        keywords = {
            "file_inclusion_words": custom_keywords.get("file_inclusion_words"),
            "open_redirect_words": custom_keywords.get("open_redirect_words"),
            "ssrf_words": custom_keywords.get("ssrf_words"),
            "xss_words": custom_keywords.get("xss_words"),
            "sqli_words": custom_keywords.get("sqli_words")
        }
    # if custom only keywords (risky parameters) list for all vuln types is provided to this function, then set it as keywords for every vuln type. (down side custom keywords list will be passed to this param_map function when --onlykeywordsall flag with arguments will be used)
    elif custom_keywords_all:
        keywords = {
            "file_inclusion_words": custom_keywords_all,
            "open_redirect_words": custom_keywords_all,
            "ssrf_words": custom_keywords_all,
            "xss_words": custom_keywords_all,
            "sqli_words": custom_keywords_all
        }
    # # if additional keywords (risky parameters) are provided to this function, then sets keywords to default + additional keywords. (down side additonal keywords will be passed to this param_map function when --addkeywords flag with arguments will be used)
    # elif additional_keywords:
    #     debug_print(f"additional keyword on {additional_keywords}")
    #     # if user didn't not provide keywords for -fileinclusion, then set file_inclusion_words key value in additional keywords dictionary to an empty list (doing this to avoid 'can only concatenate list (not "NoneType") to list' error when -fileinclusion is not used with --addkeywords flag). same logic for remaining if statements with vuln type different.
    #     if bool(additional_keywords.get("file_inclusion_words")) is False:
    #         additional_keywords["file_inclusion_words"] = []
    #     if bool(additional_keywords.get("open_redirect_words")) is False:
    #         additional_keywords["open_redirect_words"] = []
    #     if bool(additional_keywords.get("ssrf_words")) is False:
    #         additional_keywords["ssrf_words"] = []

    #     keywords = {
    #         "file_inclusion_words": file_inclusion_words_default + additional_keywords.get("file_inclusion_words"),
    #         "open_redirect_words": open_redirect_words_default + additional_keywords.get("open_redirect_words"),
    #         "ssrf_words": ssrf_words_default + additional_keywords.get("ssrf_words")
    #     }
    # if keywords (risky parameters) are not provided to this function, then set keywords to default values present in this function.
    else:
        keywords = {
            "file_inclusion_words": file_inclusion_words_default,
            "open_redirect_words": open_redirect_words_default,
            "ssrf_words": ssrf_words_default,
            "xss_words": xss_words_default,
            "sqli_words": sqli_words_default
        }

    # if removing_keywords_all and additional_keywords both are provided then remove removing_keywords_all from the keywords (going to be default after all if elif else logic above) dictionary, and THEN add the additional keywords to the keywords dictionary. Like that user can remove keywords and add keywords the same removed keyword for a specific vuln type. e.g. --removekeywordsall to --addkeywords -openredirect to (this removes keyword 'to' from all vuln types except openredirect vuln type)
    if removing_keywords_all and additional_keywords:
        # if removing_keywords_all is provided then remove then from the keywords dictionary
        keywords = {
            "file_inclusion_words": [keyword for keyword in keywords.get("file_inclusion_words") if keyword not in removing_keywords_all] + additional_keywords.get("file_inclusion_words"),
            "open_redirect_words": [keyword for keyword in keywords.get("open_redirect_words") if keyword not in removing_keywords_all] + additional_keywords.get("open_redirect_words"),
            "ssrf_words": [keyword for keyword in keywords.get("ssrf_words") if keyword not in removing_keywords_all] + additional_keywords.get("ssrf_words"),
            "xss_words": [keyword for keyword in keywords.get("xss_words") if keyword not in removing_keywords_all] + additional_keywords.get("xss_words"),
            "sqli_words": [keyword for keyword in keywords.get("sqli_words") if keyword not in removing_keywords_all] + additional_keywords.get("sqli_words")
        }
    # if removing_keywords_all list is provided then remove those keyword/keywords from the each vuln type list of keywords dictionary 
    elif removing_keywords_all:
        keywords = {
            "file_inclusion_words": [keyword for keyword in keywords.get("file_inclusion_words") if keyword not in removing_keywords_all],
            "open_redirect_words": [keyword for keyword in keywords.get("open_redirect_words") if keyword not in removing_keywords_all],
            "ssrf_words": [keyword for keyword in keywords.get("ssrf_words") if keyword not in removing_keywords_all],
            "xss_words": [keyword for keyword in keywords.get("xss_words") if keyword not in removing_keywords_all],
            "sqli_words": [keyword for keyword in keywords.get("sqli_words") if keyword not in removing_keywords_all]
        }


    # if removing_keywords dict is provided then for each vuln type provided remove its associated keyword/keywords from the each vuln type list of default keywords dictionary 
    if removing_keywords:
        # if user didn't not provide keywords for -fileinclusion, then set file_inclusion_words key value in additional keywords dictionary to an empty list (doing this to avoid 'can only concatenate list (not "NoneType") to list' error when -fileinclusion is not used with --removekeywords flag). same logic for remaining if statements with vuln type different.
        if bool(removing_keywords.get("file_inclusion_words")) is False:
            removing_keywords["file_inclusion_words"] = []
        if bool(removing_keywords.get("open_redirect_words")) is False:
            removing_keywords["open_redirect_words"] = []
        if bool(removing_keywords.get("ssrf_words")) is False:
            removing_keywords["ssrf_words"] = []
        if bool(removing_keywords.get("xss_words")) is False:
            removing_keywords["xss_words"] = []        
        if bool(removing_keywords.get("sqli_words")) is False:
            removing_keywords["sqli_words"] = [] 
        keywords = {
            "file_inclusion_words": [keyword for keyword in keywords.get("file_inclusion_words") if keyword not in removing_keywords.get("file_inclusion_words")],
            "open_redirect_words": [keyword for keyword in keywords.get("open_redirect_words") if keyword not in removing_keywords.get("open_redirect_words")],
            "ssrf_words": [keyword for keyword in keywords.get("ssrf_words") if keyword not in removing_keywords.get("ssrf_words")],
            "xss_words": [keyword for keyword in keywords.get("xss_words") if keyword not in removing_keywords.get("xss_words")],
            "sqli_words": [keyword for keyword in keywords.get("sqli_words") if keyword not in removing_keywords.get("sqli_words")]
        }


    # if removing_keywords_all list is provided then remove those keyword/keywords from the each vuln type list of keywords dictionary 
    if removing_keywords_all:
        keywords = {
            "file_inclusion_words": [keyword for keyword in keywords.get("file_inclusion_words") if keyword not in removing_keywords_all],
            "open_redirect_words": [keyword for keyword in keywords.get("open_redirect_words") if keyword not in removing_keywords_all],
            "ssrf_words": [keyword for keyword in keywords.get("ssrf_words") if keyword not in removing_keywords_all],
            "xss_words": [keyword for keyword in keywords.get("xss_words") if keyword not in removing_keywords_all],
            "sqli_words": [keyword for keyword in keywords.get("sqli_words") if keyword not in removing_keywords_all]
        }

    # writing this if logic once more even though its upside present to apply what is documented in the README.md of project which basically says: When --removekeywordsall is used with either --addkeywordsall or --addkeywords, the add option takes priority.
    if additional_keywords:
        # if user didn't not provide keywords for -fileinclusion, then set file_inclusion_words key value in additional keywords dictionary to an empty list (doing this to avoid 'can only concatenate list (not "NoneType") to list' error when -fileinclusion is not used with --addkeywords flag). same logic for remaining if statements with vuln type different.
        if bool(additional_keywords.get("file_inclusion_words")) is False:
            additional_keywords["file_inclusion_words"] = []
        if bool(additional_keywords.get("open_redirect_words")) is False:
            additional_keywords["open_redirect_words"] = []
        if bool(additional_keywords.get("ssrf_words")) is False:
            additional_keywords["ssrf_words"] = []
        if bool(additional_keywords.get("xss_words")) is False:
            additional_keywords["xss_words"] = []
        if bool(additional_keywords.get("sqli_words")) is False:
            additional_keywords["sqli_words"] = []
        keywords = {
            "file_inclusion_words": keywords.get("file_inclusion_words") + additional_keywords.get("file_inclusion_words"),
            "open_redirect_words": keywords.get("open_redirect_words") + additional_keywords.get("open_redirect_words"),
            "ssrf_words": keywords.get("ssrf_words") + additional_keywords.get("ssrf_words"),
            "xss_words": keywords.get("xss_words") + additional_keywords.get("xss_words"),
            "sqli_words": keywords.get("sqli_words") + additional_keywords.get("sqli_words")
        }

    # if additional_keywords_all list is provided then add those keyword/keywords to the each vuln type list of keywords dictionary (determined to be used after all if elif else logic above).
    if additional_keywords_all:
        keywords = {
            "file_inclusion_words": keywords.get("file_inclusion_words") + additional_keywords_all,
            "open_redirect_words": keywords.get("open_redirect_words") + additional_keywords_all,
            "ssrf_words": keywords.get("ssrf_words") + additional_keywords_all,
            "xss_words": keywords.get("xss_words") + additional_keywords_all,
            "sqli_words": keywords.get("sqli_words") + additional_keywords_all
        }

    file_inclusion = []
    open_redirect = []
    ssrf = []
    xss = []
    sqli = []

    #! Do not use elif statements here because a parameter might match multiple vulnerability types
    for parameter in parameters:
        # if --nostrict flag is passed, partial match of vulnerable keyword to parameter name also results in detection
        if nostrict:
            for word in keywords.get("file_inclusion_words"):
                if word in parameter.lower():  # parameter.lower() converts the parameter name to lowercase to ensure case-insensitive matching input parameters to keywords (risky parameters). This means input parameter names like 'TO', 'to', or 'To' will all match the same keyword ('to').
                    file_inclusion.append(parameter)  # appends the original parameter (with its original casing) to the output list. We avoid lowercasing here to preserve the original user's input case in terminal output.
            for word in keywords.get("open_redirect_words"):
                if word in parameter.lower():
                    open_redirect.append(parameter)
            for word in keywords.get("ssrf_words"):
                if word in parameter.lower():
                    ssrf.append(parameter)
            for word in keywords.get("xss_words"):
                if word in parameter.lower():
                    xss.append(parameter)
            for word in keywords.get("sqli_words"):
                if word in parameter.lower():
                    sqli.append(parameter)

        # if --nostrict flag is not passed, partial match of vulnerable keyword to paramter name does not results in detection (strict checking)
        else:
            if parameter.lower() in keywords.get("file_inclusion_words"):
                file_inclusion.append(parameter)
            if parameter.lower() in keywords.get("open_redirect_words"):
                open_redirect.append(parameter)
            if parameter.lower() in keywords.get("ssrf_words"):
                ssrf.append(parameter)
            if parameter.lower() in keywords.get("xss_words"):
                xss.append(parameter)
            if parameter.lower() in keywords.get("sqli_words"):
                sqli.append(parameter)

    risk_mapping = {"file_inclusion": file_inclusion, "open_redirect": open_redirect, "ssrf": ssrf, "xss": xss, "sqli": sqli}

    # if all values in risk_mapping dictionary are empty lists (no parameter matched some or any category/categories of vulnerability keywords)
    if all(not v for v in risk_mapping.values()):
        return {}
    # if any values in risk_mapping dictionary not are empty lists (some parameter matched one or some category/categories of vulnerability keywords)
    else:
        return risk_mapping


def map_vulntype_to_keywords(raw_args):
    """
    Parses a list of arguments to map vulntype -flag(s) (vuln types) to their associated keywords (parameters).

    Args:
        raw_args (list): Raw list of arguments passed after --onlykeywords

    Returns:
        dict: A dictionary where each vulnerability type maps to a list of its keywords
    """
    lists = defaultdict(list)  # Dictionary to store vuln type and its parameters → keywords mapping
    current_key = None         # Tracks the current vuln type (e.g., 'ssrf', 'openredirect')

    for arg in raw_args:
        # If a new flag encountered (could be any of --onlykeywords, --addkeywords), return the map of vuln type & keywords collected till now
        if arg.startswith('--'):  # New flag encountered (could be any of --onlykeywords, --addkeywords). #! don't remove this line from here
            return lists
        elif arg.startswith('-'):
            # New vuln type flag encountered (e.g., '-ssrf'), strip the dash
            current_key = arg.lstrip('-')
            lists[current_key] = []  # Initialize a list for this key
        elif current_key:
            # If currently inside a vuln type section, append the keyword to its list
            lists[current_key].append(arg)

    return lists


def validate_and_create_vulntypes_keywords(parsed_lists):
    """Validates the provided vuln types (e.g. ssrf) & keywords (risky paramters) to be standard & Returns a dictionary containing their mapping.

    Args:
        parsed_lists (_type_): It will be a dict_items type containing vuln type and all the keywords (parameters).

    Returns:
        (dict or False): If the provided vuln types are valid, returns a dictionary containing provided vuln types (e.g. ssrf) & its associated keywords (risky parameters). If the provided vuln types are not valid returns False.
    """
    # initialize a vuln type to keywords (parameters) mapping dictionary
    vuln_to_keywords = {
        "file_inclusion_words": [],
        "open_redirect_words": [],
        "ssrf_words": [],
        "xss_words": [],
        "sqli_words": []
    }

    ## Updates the vuln_to_keywords dictionary with provided keywords (parameters) for each vuln type.

    parsed_lists_dict = dict(parsed_lists.items())
    
    # For each vuln type name (e.g., -ssrf) and its associated keywords (parameters) provided to function, add them to the vuln_to_keywords dictionary if the provided vuln type name is a valid standard name.
    for vulntype in parsed_lists_dict.keys():
        vuln_keywords = parsed_lists_dict.get(vulntype)  # contains all keywords (paramters) provided by user in cli for current vuln type
        debug_print(vulntype, vuln_keywords)

        # if the vuln type provided in function (down the road these will be taken from --onlykeywords/--addkeywords/--removekeyword) is not correct, exit the program reporting user about the issue.
        if vulntype not in valid_vulntype_names:
            return False
            # sys.exit(1)
        # fill the vuln_to_keywords empty dictionary with mapping of vuln type and its keywords provided to function (down the road these will be taken via cli arguments --onlykeywords/--addkeywords/--removekeyword)
        elif vulntype in valid_vulntype_names:
            if vulntype == "fileinclusion":
                vulntype = "file_inclusion_words"
            elif vulntype == "openredirect":
                vulntype = "open_redirect_words"
            elif vulntype == "ssrf":
                vulntype = "ssrf_words"
            elif vulntype == "xss":
                vulntype = "xss_words"
            elif vulntype == "sqli":
                vulntype = "sqli_words"

            vuln_to_keywords[vulntype] = vuln_keywords

    # return parsed_lists_dict
    return vuln_to_keywords


# ensures the script runs only when executed (not imported).
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=f"A script to map parameter names to commonly associated vulnerability types. \nValid vuln type names: {valid_vulntype_names}.", epilog="TIP: You can remove a keyword globally for all vuln types with --removekeywordsall, and reassign the same keyword for only a specific vuln type using --removekeywordsall and --addkeywords at the same time. For example: --removekeywordsall to --addkeywords -openredirect to. This removes the keyword 'to' from all vuln types except 'openredirect'.\n\nHow --addkeywords and --addkeywordsall interact with --removekeywords.\n\t- When --removekeywordsall and --addkeywordsall are used together, --addkeywordsall takes precedence and re-adds the removed keywords globally.\n\t- When --removekeywordsall and --addkeywords are used together, --addkeywords takes precedence and reassigns the removed keywords to the specified vuln types.", formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument(
        "--nocolour",
        action="store_true",
        help="Disable colour output. (default: False)"
    )
    parser.add_argument(
        "--nostrict",
        action="store_true",
        help="Disable strict checking, which means a partial match of a vulnerable keyword to a parameter name will result in detection (default: False). Note: This option does not affect --removekeywordsall & --removekeywords."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debugging messages. (default: False)"
    )
    parser.add_argument(
        "--removekeywordsall",
        nargs="+",
        type=str.lower,
        help=f"Remove these keywords from the tool's default keywords (risky parameter names) for ALL vuln types (globally). This argument is not needed to come last after all other cli options. Example: --removekeywords param1 param2"
    )
    parser.add_argument(
        "--onlykeywordsall",
        nargs="+",
        type=str.lower,
        help="Ignore the tool's default keywords (risky parameter names). Use only these keywords for ALL vuln types (globally). This argument is not needed to come last after all other cli options. Example: --onlykeywordsall param1 param2"
    )
    parser.add_argument(
        "--addkeywordsall",
        nargs="+",
        type=str.lower,
        help=f"Add these keywords to the tool's default keywords (risky parameter names) for ALL vuln types (globally). This argument is not needed to come last after all other cli options. Example: --addkeywordsall param1 param2"
    )
    parser.add_argument(
        "--removekeywords",
        nargs=argparse.REMAINDER,
        type=str.lower,
        help=f"For each specified vuln type, remove the corresponding keywords provided from the tool's default keywords (risky parameter names) for that vuln type. This argument SHOULD come last, after all other command-line options. Example: --removekeywords -ssrf param1 param2 -openredirect param2 param3"
    )
    # Collects vulntype flag(s) [name of vulnerability] and their associated custom keywords [parameter names]
    parser.add_argument(
        "--onlykeywords",
        nargs=argparse.REMAINDER,
        type=str.lower,
        help=f"Ignore the tool's default keywords (risky parameter names). Use only these specified vuln types and their corresponding custom keywords (risky parameter names). This argument SHOULD come last, after all other command-line options. Example: --onlykeywords -ssrf param1 param2"
    )
    parser.add_argument(
        "--addkeywords",
        nargs=argparse.REMAINDER,
        type=str.lower,
        help=f"Use tool's default keywords (risky paramter names) as well as these additional keywords for specified vuln types. This argument SHOULD come last, after all other command-line options. Example: --addkeywords -ssrf param1 param2"
    )
    parser.add_argument(
        "--showdefault",
        action="store_true",
        help="Show default keywords used by ParamSage and exit."  # default value False
    )

    argcomplete.autocomplete(parser)
    # Parse the arguments
    args = parser.parse_args()

    nocolour = args.nocolour
    nostrict = args.nostrict
    debug = args.debug
    removekeywordsall = args.removekeywordsall  # all keywords from --removekeywordsall in a list (argparse will understand separation of this flag and its values from other flags automatically, so no need to worry about conflicts with other flags)
    onlykeywordsall = args.onlykeywordsall  # all keywords from --onlykeywordsall in a list (argparse will understand separation of this flag and its values from other flags automatically, so no need to worry about conflicts with other flags)
    addkeywordsall = args.addkeywordsall  # all keywords from --addkeywordsall in a list (argparse will understand separation of this flag and its values from other flags automatically, so no need to worry about conflicts with other flags)
    removekeywords = args.removekeywords
    onlykeywords = args.onlykeywords
    addkeywords = args.addkeywords
    showdefault = args.showdefault


    # If --nocolour flag is passed via command line, then colour colour variabes won't make effect in code even if they are used
    if nocolour is True:
        RESET = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        PINK = ""
    else:
        # ANSI escape codes to color specific parts of printed output for visibility and categorization.
        RESET = "\033[0m"
        BLUE = "\033[94m"
        MAGENTA = "\033[35m"
        CYAN = "\033[96m"
        PINK = "\033[95m"

    #! debug_print does NOT print regex results
    # passing f-strings to debug_print function - this function can handle f-strings directly (e.g., debug_print(f"one plus one = {1+1}")) and f-strings in variables passed as f-strings (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(f"{1plus1}")), but not f-string variables directly (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(1plus1)).
    def debug_print(message, newline=False):
        """If debug_mode is enabled, prints debug messages from wherever it is called.

        Args:
            message (str): The message to be printed. This can be a regular string or an f-string.
            newline (bool, optional): If True, prints message with formatting and a separator. Defaults to False.
        """
        if debug and newline:
            cyan_line = f"{CYAN}{'-' * 150}{RESET}"
            print(f"{PINK}\n\n\n{cyan_line}\nDebug: {message}{RESET}")
        elif debug:
            print(f"{PINK}Debug: {message}{PINK}")

    # print(f"all args passed: {list(args)}")

    if showdefault:
        param_map(parameters=False, show_default=True)

    ## Checks for mutually exclusive CLI options. If both are used together, the tool exits and informs the user that they can't do that.
    all_raw_args = sys.argv[1:]
    debug_print(f"All arguments passed to tool raw: {all_raw_args}")
    #! Always keep this mutual exclusion check before any code lines that uses --onlykeywords or --addkeywords.
    # Exits if both --onlykeywords and (--addkeywords/--removekeywords) are present in all cli arguments, since they are mutually exclusive and cannot be used together.
    if "--onlykeywords" in all_raw_args and "--addkeywordsall" in all_raw_args:
        print("--onlykeywords and --addkeywordsall cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywords" in all_raw_args and "--addkeywords" in all_raw_args:
        print("--onlykeywords and --addkeywords cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywords" in all_raw_args and "--removekeywordsall" in all_raw_args:
        print("--onlykeywords and --removekeywordsall cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywords" in all_raw_args and "--removekeywords" in all_raw_args:
        print("--onlykeywords and --removekeywords cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    # Exits if both --onlykeywords and --onlykeywordsall are present in all cli arguments.
    if "--onlykeywords" in all_raw_args and "--onlykeywordsall" in all_raw_args:
        print("--onlykeywords and --onlykeywordsall cannot be used at the same time.")
        sys.exit(1)
    # Exits if both --onlykeywordsall and (--addkeywordsall/--addkeywords/--removekeywordsall/--removekeywords) are present in all cli arguments, since they are mutually exclusive and cannot be used together.
    if "--onlykeywordsall" in all_raw_args and "--addkeywordsall" in all_raw_args:
        print("--onlykeywordsall and --addkeywordsall cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywordsall" in all_raw_args and "--addkeywords" in all_raw_args:
        print("--onlykeywordsall and --addkeywords cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywordsall" in all_raw_args and "--removekeywordsall" in all_raw_args:
        print("--onlykeywordsall and --removekeywordsall cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--onlykeywordsall" in all_raw_args and "--removekeywords" in all_raw_args:
        print("--onlykeywordsall and --removekeywords cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    # Exits if both --removekeywords and --removekeywordsall are present in all cli arguments.
    if "--removekeywords" in all_raw_args and "--removekeywordsall" in all_raw_args:
        print("--removekeywords and --removekeywordsall cannot be used at the same time.")
        sys.exit(1)
    # Exits if both --removekeywords and (--onlykeywords/--addkeywords) are present in all cli arguments.
    if "--removekeywords" in all_raw_args and "--onlykeywords" in all_raw_args:
        print("--removekeywords and --onlykeywords cannot be used at the same time. Using them together doesn't make sense anyway.")
        sys.exit(1)
    elif "--removekeywords" in all_raw_args and "--addkeywords" in all_raw_args:
        print("--removekeywords and --addkeywords cannot be used at the same time. Using them together DOES make sense. This is a limitation of ParamSage. To work around this, refer to the Tip section in the --help output.")
        sys.exit(1)


    #! Only the first of --onlykeywords or --addkeywords will be processed.  If --onlykeywords appears first, all arguments after it (including --addkeywords and its subargs) will be treated as its subargs.  Likewise, if --addkeywords appears first, --onlykeywords will not be treated as an arg.  This is because argparse includes all following arguments as part of the first flag’s values.  To handle this, map_vulntype_to_keywords stops parsing subargs when it encounters another flag starting with '--'.
    # if --onlykeywords argument provided in cli
    if args.onlykeywords:
        # set onlykeywords to True, which later determines that only user provided vuln type keywords should be used and not the default ones.
        onlykeywords = True
    # if --addkeywords argument provided in cli
    if args.addkeywords:
        # set addkeywords to True, which later determines that user provided vuln type keywords should be used in addition to default ones.
        addkeywords = True
    if args.removekeywordsall:
        # set removekeywordsall to True, which later determines that user provided vuln type keywords should not be used (should be removed from in additional and default keywords).
        removekeywordsall = True
    if args.removekeywords:
        removekeywords = True
    else:
        to_remove_keywords = False
    if args.addkeywordsall:
        addkeywordsall = True
    if args.onlykeywordsall:
        onlykeywordsall = True

    # if (onlykeywords is True) and (addkeywords is True):
    #     print("--onlykeywords and --addkeywords cannot be used at the same time.")
    #     sys.exit(1)

    if onlykeywords is True:
        parsed_lists = map_vulntype_to_keywords(args.onlykeywords)  # it contains a dict_items type containing vuln type and all the keywords (parameters) provided for it provided in cli argument
        parsed_lists_dict = validate_and_create_vulntypes_keywords(parsed_lists=parsed_lists)  # it contains the dictionary version of above dict_items type containing vuln type and all the keywords (parameters) ONLY IF each vuln type (e.g. -ssrf) is valid standard one, if any of the vuln type is not valid it contains False.
        # if any of the vuln type provided in cli using --onlykeywords is invalid, exits the tool.
        if parsed_lists_dict is False:
            print(f"Incorrect vuln type name. Valid vuln type names: {valid_vulntype_names}")
            sys.exit(1)
        # if all of the vuln type provided in cli using --onlykeywords are valid, puts the provided vuln types (e.g. -ssrf) & their associated keywords (risky parameters) in dict type to vuln_to_keywords.
        else:
            vuln_to_keywords = parsed_lists_dict

    if addkeywords is True:
        parsed_lists = map_vulntype_to_keywords(args.addkeywords)  # it contains a dict_items type containing vuln type and all the keywords (parameters) provided for it provided in cli argument
        parsed_lists_dict = validate_and_create_vulntypes_keywords(parsed_lists=parsed_lists)  # it contains the dictionary version of above dict_items type containing vuln type and all the keywords (parameters) ONLY IF each vuln type (e.g. -ssrf) is valid standard one, if any of the vuln type is not valid it contains False.
        # if any of the vuln type provided in cli using --addkeywords is invalid, exits the tool.
        if parsed_lists_dict is False:
            print(f"Incorrect vuln type name. Valid vuln type names: {valid_vulntype_names}")
            sys.exit(1)
        # if all of the vuln type provided in cli using --addkeywords are valid, puts the provided vuln types (e.g. -ssrf) & their associated keywords (risky parameters) in dict type to vuln_to_keywords.
        else:
            vuln_to_keywords = parsed_lists_dict

    if removekeywords is True:
        parsed_lists = map_vulntype_to_keywords(args.removekeywords)  # it contains a dict_items type containing vuln type and all the keywords (parameters) provided for it provided in cli argument
        parsed_lists_dict = validate_and_create_vulntypes_keywords(parsed_lists=parsed_lists)  # it contains the dictionary version of above dict_items type containing vuln type and all the keywords (parameters) ONLY IF each vuln type (e.g. -ssrf) is valid standard one, if any of the vuln type is not valid it contains False.
        # if any of the vuln type provided in cli using --removekeywords is invalid, exits the tool.
        if parsed_lists_dict is False:
            print(f"Incorrect vuln type name. Valid vuln type names: {valid_vulntype_names}")
            sys.exit(1)
        # if all of the vuln type provided in cli using --removekeywords are valid, puts the provided vuln types (e.g. -ssrf) & their associated keywords (risky parameters) in dict type to vuln_to_keywords.
        else:
            to_remove_keywords = parsed_lists_dict

    # If --removekeywordsall is used, store the provided keywords in to_remove_keywords_all as a list. argparse ensures at least one value is supplied, otherwise it exits the program and informs user. Else set removekeywords to False.
    if removekeywordsall is True:
        to_remove_keywords_all = args.removekeywordsall  # list containing all keywords provided after --removekeywordsall
    # Else, sets to_remove_keywords to False to avoid NameError: name 'to_remove_keywords' is not defined.' in risk_mapping if --removekeywordsall is not used in cli args.
    else:
        to_remove_keywords_all = False

    # If --addkeywordsall is used, store the provided keywords in to_add_keywords_all as a list. argparse ensures at least one value is supplied, otherwise it exits the program and informs user.
    if addkeywordsall is True:
        to_add_keywords_all = args.addkeywordsall  # list containing all keywords provided after --addkeywordsall
    # Else, sets to_add_keywords_all to False to avoid NameError: name 'to_add_keywords_all' is not defined.' in risk_mapping if --addkeywordsall is not used in cli args.
    else:
        to_add_keywords_all = False

    # If --onlykeywordsall is used, store the provided keywords in only_keywords_to_use_all as a list. argparse ensures at least one value is supplied, otherwise it exits the program and informs user. 
    if onlykeywordsall is True:
        only_keywords_to_use_all = args.onlykeywordsall
    # Else, sets only_keywords_to_use_all  to False to avoid NameError: name 'only_keywords_to_use_all ' is not defined.' in risk_mapping if --onlykeywordsall is not used in cli args.
    else:
        only_keywords_to_use_all = False


    # # for debugging purpose taking urls from a file, comment it when done with debugging
    # with open("testbed/urls.txt", "r") as file:
    #     urls = file.readlines()
    # for url in urls:

    # Read lines (urls) from stdin
    for url in sys.stdin:
        url = url.strip()
        if url:
            url, parameters = detect_paramters(url)

            # If --onlykeywords flag is used, use the CLI-provided keywords (risky parameters) for each vuln type
            if args.onlykeywords:
                risk_mapping = param_map(parameters=parameters, custom_keywords=vuln_to_keywords)  # if --onlykeywords is used, using --removekeywords/--removekeywordsall/--addkeywordsall doesn't make sense.
                debug_print(f"parameters: {parameters}, vuln_to_keywords: {vuln_to_keywords}")
            # If --onlykeywordsall flag is used, use the the same CLI-provided keywords (risky parameters) for all vuln type
            elif args.onlykeywordsall:
                risk_mapping = param_map(parameters=parameters, custom_keywords_all=only_keywords_to_use_all)  # if --onlykeywordsall is used, using --removekeywords/--removekeywordsall/--addkeywordsall doesn't make sense. also --onlykeywords & --onlykeywordsall should be mutually exclusive.
            # If --addkeywords flag is used, use the CLI-provided keywords (risky parameters) for each vuln type in addition to default ones
            elif args.addkeywords:
                risk_mapping = param_map(parameters=parameters, additional_keywords=vuln_to_keywords, removing_keywords_all=to_remove_keywords_all, additional_keywords_all=to_add_keywords_all)  # here also passing additional_keywords_all so if the user use --addkeywordsall simultaneously with --addkeywords, tool can have the keywords provided via --addkeywordsall to add to the keywords (risky params) which will be used to determine if a url's parameter is risky or not. here not passing to_remove_keywords coz upside in the mutually exclusive cli options it is not allowed anyway which is a correct thing.
                debug_print(f"parameters: {parameters}, vuln_to_keywords: {vuln_to_keywords}")
            # If --addkeywordsall flag is used, use the CLI-provided keywords (risky parameters) for all vuln type in addition to default ones
            elif args.addkeywordsall:
                risk_mapping = param_map(parameters=parameters, removing_keywords_all=to_remove_keywords_all, removing_keywords=to_remove_keywords, additional_keywords_all=to_add_keywords_all)
            # Otherwise, use the tool's default keywords to detect risky parameters for each vuln type
            else:
                risk_mapping = param_map(parameters=parameters, removing_keywords_all=to_remove_keywords_all, removing_keywords=to_remove_keywords)
            # print(url, risk_mapping)
            
            # if param_map doesn't return an empty dictionary
            if risk_mapping:
                # print(risk_mapping)
                # Removes dict values with empty lists so only vulnerability types with associated risky parameters detected are included in the output
                filtered_risk_mapping = {
                    vuln_type: params
                    for vuln_type, params in risk_mapping.items()
                    if params
                }

                debug_print(url, filtered_risk_mapping)
                # issues = ", ".join(f"{MAGENTA}{vuln_type}{RESET}: {params}" for vuln_type, params in filtered_risk_mapping.items())

                # Hacky solution: remove underscores from vuln type names in output. Reasoning behind doing this is from the user's perspective, standard vuln types in this tool are written as single words (e.g., fileinclusion, openredirect, ssrf), so we strip underscores to match that convention.
                issues = ", ".join(
                    f"{MAGENTA}{vuln_type.replace('_', '')}{RESET}: [{', '.join(params)}]"
                    for vuln_type, params in filtered_risk_mapping.items()
                )

                print(f"{BLUE}{url}{RESET} {issues}")
