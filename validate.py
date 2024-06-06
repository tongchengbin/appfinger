import json
import logging
import os
import re

import yaml


def getAllFilenames():
    """
        迭代目录下的所有文件
    :return:
    """
    # 获取当前所有漏洞
    all_matchers = []
    for root, dirs, files in os.walk("app"):
        print(root, dirs, files)
        for file in files:
            filename = os.path.join(root, file)
            if not filename.endswith(".yaml"):
                continue
            with open(filename, encoding='utf-8') as f:
                data = yaml.load(f, Loader=yaml.FullLoader)
            all_matchers += data
    return all_matchers


def main():
    new_matchers = []
    all_matchers = getAllFilenames()
    for matcher in all_matchers:
        bk = False
        new_matcher = {
            "name": matcher["name"],
            "matchers": []
        }
        matcher_condition = matcher.get("matchers-condition")
        if matcher_condition == "and":
            new_matcher["condition"] = matcher_condition
        for part in matcher["matchers"]:
            if "type" not in part:
                print("not part type :{}".format(part))
                if matcher_condition == "and":
                    bk = True
                    break
                else:
                    continue
            if part["type"] == "regex" and part["regex"]:
                for r in part["regex"]:
                    try:
                        re.compile(r)
                    except:
                        if matcher_condition == "and":
                            bk = True
                            break
                        else:
                            continue
            if part["type"] == "word" and not [i for i in part["words"] if i]:
                if matcher_condition == "and":
                    bk = True
                    break
                else:
                    continue
            new_matcher["matchers"].append(part)
        if bk:
            continue
        if not new_matcher["matchers"]:
            continue
        new_matchers.append(new_matcher)
    with open('app/web.yaml', 'w') as f:
        f.write(yaml.dump(new_matchers, indent=2))


if __name__ == "__main__":
    main()
