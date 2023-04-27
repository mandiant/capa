import os
import yaml

def findall_features(features):
    feature_list = []
    for feature in features:
        if 'and' in feature:
            and_list = findall_features(feature['and'])
            for x in and_list:
                feature_list.append(x)
        elif 'or' in feature:
            or_list = findall_features(feature['or'])
            for y in or_list:
                feature_list.append(y)
        else:
            feature_list.append(feature)
    return feature_list

def find_overlapping_rules(new_rule_path, rules_path):
    if not new_rule_path.endswith('.yml'):
        return 'ERROR ! New rule path file name incorrect'
    
    count = 0

    with open(new_rule_path, 'r') as f:
        new_rule = yaml.safe_load(f)
    if 'rule' not in new_rule:
        return "ERROR ! given new rule path isn't a rule"
    
    new_rule_features = findall_features(new_rule['rule']['features'])

    overlapping_rules = []
    
    for dirpath, dirnames, filenames in os.walk(rules_path):
        for filename in filenames:
            if filename.endswith('.yml'):
                rule_path = os.path.join(dirpath, filename)
                with open(rule_path, 'r') as f:
                    rule = yaml.safe_load(f)
                    if 'rule' not in rule:
                        continue
                    rule_features = findall_features(rule['rule']['features'])
                    count+=1
                if any([feature in rule_features for feature in new_rule_features]):
                    overlapping_rules.append(rule_path)
    result = {'overlapping_rules': overlapping_rules,
              'count': count}
    
    return result

# usage
base_dir = ''
new_rule_path = base_dir + 'rules\\anti-analysis\\reference-analysis-tools-strings.yml'
rules_path = base_dir + 'rules'

try:
    result = find_overlapping_rules(new_rule_path, rules_path)
    print('New rule path : %s' % new_rule_path)
    print('Number of rules checked : %s ' % result['count'])
    print('Paths to overlapping rules : ', result['overlapping_rules'])
    print('Number of rules containing same features : %s' % len(result['overlapping_rules']))
except Exception as e:
    print(e)
    try:
        print(result,'')
    except:
        pass
