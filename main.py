import os
import stat
from functools import reduce
from shutil import rmtree
from tempfile import mkdtemp

from git import Repo
from netaddr import IPNetwork, cidr_merge


class Rule(object):
    def __init__(self):
        self.name = ''
        self.friendly_name = ''
        self.proxy_type = 0
        self.proxy_type_2 = 0
        self.unknown_1 = 1
        self.unknown_2 = 0
        self.writeable = 1
        self.dns_type = 0
        self.comment = ''
        self.network_list = list()

    @staticmethod
    def parse_header(data):
        data = data.strip()
        data.replace(',', '')
        return data

    @staticmethod
    def parse(repo: 'RuleRepo', rule_index: int) -> 'Rule':
        new_rule = Rule()
        rule_path = os.path.join(repo.rules_path, repo.rules_list[rule_index])
        with open(rule_path, 'r', encoding='utf8') as f:
            lines = f.readlines()

        header = lines[0]
        if header.startswith('#'):
            header = header[1:]
        header_list = header.split(',')
        new_rule.name = Rule.parse_header(header_list[0])
        new_rule.friendly_name = Rule.parse_header(header_list[1])
        new_rule.proxy_type = Rule.parse_header(header_list[2])
        new_rule.proxy_type_2 = Rule.parse_header(header_list[3])
        new_rule.unknown_1 = Rule.parse_header(header_list[4])
        new_rule.unknown_2 = Rule.parse_header(header_list[5])
        new_rule.writeable = Rule.parse_header(header_list[6])
        new_rule.dns_type = Rule.parse_header(header_list[7])
        new_rule.comment = Rule.parse_header(header_list[8])

        network_list = list()
        for line in lines[1:]:
            line = line.strip()
            line.replace('\n', '')
            line.replace('\r', '')
            try:
                network = IPNetwork(line)
            except:
                continue
            network_list.append(network)

        new_rule.network_list = cidr_merge(network_list)
        return new_rule

    def output(self) -> str:
        header = '#{0},{1},{2},{3},{4},{5},{6},{7},{8}'.format(self.name,
                                                               self.friendly_name,
                                                               self.proxy_type,
                                                               self.proxy_type_2,
                                                               self.unknown_1,
                                                               self.unknown_2,
                                                               self.writeable,
                                                               self.dns_type,
                                                               self.comment)
        content = "\n".join(map(lambda x: str(x), self.network_list))
        return '{0}\n{1}'.format(header, content)

    def __and__(self, other: 'Rule') -> 'Rule':
        new_rule = Rule()
        new_rule.name = '{0} && {1}'.format(self.name, other.name)
        new_rule.friendly_name = '{0} && {1}'.format(self.friendly_name, other.friendly_name)
        new_rule.comment = '{0} && {1}'.format(self.comment, other.comment)
        self.network_list.extend(other.network_list)
        new_rule.network_list = cidr_merge(self.network_list)
        return new_rule


class RuleRepo(object):
    def __init__(self):
        self.temp_path = mkdtemp()
        self.repo = Repo.clone_from(url="https://github.com/FQrabbit/SSTap-Rule.git", to_path=self.temp_path)

        self.rules_path = os.path.join(self.temp_path, 'rules')
        rules_walk = os.walk(self.rules_path)
        self.rules_list = next(rules_walk)[2]

    def combine(self, combine_list: list) -> Rule:
        new_rule = reduce(lambda x, y: x & y, map(lambda x: Rule.parse(repo, x), combine_list))
        return new_rule


def remove_readonly(func, path, _):
    "Clear the readonly bit and reattempt the removal"
    os.chmod(path, stat.S_IWRITE)
    func(path)


if __name__ == '__main__':
    repo = RuleRepo()
    for index in range(len(repo.rules_list)):
        print('{0}: {1}'.format(index, Rule.parse(repo, index).friendly_name))

    index_raw = input('Index List: ')
    index_list = list(map(lambda x: int(x.strip()), index_raw.split(',')))
    rule = repo.combine(index_list)
    with open('{0}.rules'.format(rule.name), 'w', encoding='utf8') as f:
        f.write(rule.output())

    repo.repo.close()
    rmtree(repo.temp_path, onerror=remove_readonly)
