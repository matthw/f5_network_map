#!/usr/bin/python
# generate a visual network map of an F5 partition
# 2018 Matthieu Walter

import requests
import urllib3
import json
import argparse
import sys
import time
import os
import re
from socket import gethostbyname
from fnmatch import fnmatch
from random import randint
from graphviz import Digraph
from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError

HOST = None
USER = ""
PASS = ""


VS = []
DATAGROUP = {}
POOLS = {}


# suppress warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def parse_destination(dest):
    ''' return ip/port from strings like that:
        '/Partition2/10.195.0.49%2:443'
    '''
    return re.findall('^(?:/.*?/)?([0-9.]+)(?:%[0-9])?:([0-9]+)$', dest)[0]



def pool_from_name(poolname, default_partition):
    ''' return a Pool object from its name.
    '''
    if poolname.startswith('/'):
        part, name = poolname.split('/')[1:]
    else:
        part = default_partition
        name = poolname

    if not POOLS.has_key(part):
        POOLS[part] = {}

    if not POOLS[part].has_key(name):
        POOLS[part][name] = Pool(part, name)

    return (part, name)


class Conf:
    mgt = None


class VirtualServer:
    ''' TODO: get automap and snat pools ip addr
    '''
    def __init__(self, vs_obj):
        self.vs = vs_obj

        self.name = self.vs.name
        self.partition = self.vs.partition
        self.ipaddr, self.port = parse_destination(self.vs.destination)


        self.ssl_client = False
        self.ssl_server = False

        self.description = None

        # snat can be:
        # {u'type': u'snat', u'poolReference': {u'link': u'https://xxxx'}, u'pool': u'/Partition1/snat_something'}
        # {u'type': u'automap'}
        if self.vs.sourceAddressTranslation.has_key('type'):
            if self.vs.sourceAddressTranslation['type'] == 'automap':
                self.snat = 'automap'
            elif self.vs.sourceAddressTranslation['type'] == 'snat':
                self.snat = self.vs.sourceAddressTranslation['pool']
            elif self.vs.sourceAddressTranslation['type'] == 'none':
                self.snat = 'no_source_nat'
        else:
            self.snat = '???'


        # if no default pool, the attribute doesn't exist
        self.pools = set()
        if hasattr(self.vs, 'pool'):
            self.pools.add(pool_from_name(self.vs.pool, self.partition))

        # if no irule attached, the attribute doesn't exist
        if hasattr(self.vs, 'rules'):
            self.rules = self.vs.rules
            self._look_for_pools_in_irules()
        else:
            self.rules = []


        # look for description
        if hasattr(self.vs, 'description'):
            self.description = self.vs.description


        if hasattr(self.vs, 'enabled'):
            self.enabled = self.vs.enabled
        else:
            self.enabled = False

        self._parse_profiles()
        self._look_for_proxypass()


    def _ignore_profile(self, profile_name):
        ''' skip known non-ssl profiles
        '''
        _skip_profile = ['fastL4', 'fastL4-*', 'tcp', 'tcp-*-optimized', 'udp', 'http']

        for pattern in _skip_profile:
            if fnmatch(profile_name, pattern):
                return True
        return False
        

    def _parse_profiles(self):
        ''' check for client/server ssl profiles
        '''

        for profile in self.vs.profiles_s.get_collection():
            # skip known non-ssl profiles
            if self._ignore_profile(profile.name):
                continue
            if profile.context == "clientside":
                try:
                    pobj = Conf.mgt.tm.ltm.profile.client_ssls.client_ssl.load(
                                partition=profile.partition,
                                name=profile.name)
                    self.ssl_client = True
                except iControlUnexpectedHTTPError:
                    # not an ssl profile
                    self.ssl_client = False

            elif profile.context == "serverside":
                try:
                    pobj = Conf.mgt.tm.ltm.profile.server_ssls.server_ssl.load(
                                partition=profile.partition,
                                name=profile.name)
                    self.ssl_server = True
                except iControlUnexpectedHTTPError:
                    # not an ssl profile
                    self.ssl_server = False


    def _look_for_pools_in_irules(self):
        ''' lame attempt at getting pools from irules
        '''
        for rule in self.rules:
            # comes in the form /partition/rulename
            # needs to be split for loading

            # XXX tmp fix for iapps
            if rule.count("/") > 2:
                continue

            part, name = rule.split('/')[1:]
            content = Conf.mgt.tm.ltm.rules.rule.load(partition=part, name=name).apiAnonymous

            pools = re.findall('(?m)(?:^|[^#][\s]+)pool\s+([^\s]+)', content)
            for p in pools:
                # skip pools that looks like a variable or a function
                # because i'm not that smart
                if p[0] in ('$', '['):
                    continue

                #print "%s/%s"%(name, p)
                # i know the regex is broken with some comments
                try:
                    self.pools.add(pool_from_name(p, self.partition))
                except iControlUnexpectedHTTPError:
                    pass


    def _look_for_proxypass(self):
        ''' look for proxypass - half broken crap
        '''
        doit = False
        for rule in self.rules:
            # XXX tmp fix for iapps
            if rule.count("/") > 2:
                continue

            part, name = rule.split('/')[1:]
            if 'proxypass' in name:
                doit = True

        if not doit:
            return

        # check if there's a proxypass for our ip addr
        if DATAGROUP.has_key(self.ipaddr):
            # merge pool list
            self.pools |= DATAGROUP[self.ipaddr]



class Pool:
    # list of unique pools based on members, not names
    # probably the shittiest way to do it
    internal_unique = {}

    def __init__(self, partition, name):
        self.partition = partition
        self.name = name

        self._pool = self._find_pool()
        self.availability, self.state = self._status()
        

        # boolean for vailability
        self.available = self.availability == "available" and self.state == "enabled"

        # get pool members' name
        self.members = sorted([m.name for m in self._pool.members_s.get_collection()])

        self.uniqpool = self._find_unique()

    def _find_pool(self):
        return Conf.mgt.tm.ltm.pools.pool.load(partition=self.partition, name=self.name)


    def _status(self):
        ''' return (availability, state)
        availability in 
            available
            offline
        state in 
            enabled
        '''
        state = self._pool.stats.load()
        entries = state.entries[state.entries.keys()[0]]['nestedStats']['entries']

        return (entries['status.availabilityState']['description'], entries['status.enabledState']['description']) 
        


    def _find_unique(self):
        for k, v in Pool.internal_unique.items():
            if v == self.members:
                return k

        Pool.internal_unique[id(self)] = self.members
        return id(self)



def list_all_vs(partition=None):
    ''' returns a list of virtual servers
        if partition == None, returns all vs
        else return vs matching the partition
    '''
    if partition is None:
        return Conf.mgt.tm.ltm.virtuals.get_collection()
    else:
        return [v for v in Conf.mgt.tm.ltm.virtuals.get_collection() if v.partition == partition]
   

def load_datagroup_list(partition=None):
    ''' load data group lists and pools
    '''
    global DATAGROUPS

    if partition is None:
        dglist = [d for d in Conf.mgt.tm.ltm.data_group.internals.get_collection() if d.name.startswith('ProxyPass_')]
    else:
        dglist = [d for d in Conf.mgt.tm.ltm.data_group.internals.get_collection() if d.name.startswith('ProxyPass_') \
                                                                                and   d.partition == partition]

    # iterates over dg, resove hostname
    # get pools
    for dg in dglist:
        hostname = dg.name[10:]
        try:
            ip = gethostbyname(hostname)
        except:
            continue

        if not hasattr(dg, 'records'):
            continue

        pools = set()
        for rec in dg.records:
            if len(rec['data'].split()) > 1:
                try:
                    pools.add(pool_from_name(rec['data'].split()[1], dg.partition))
                except iControlUnexpectedHTTPError:
                    print("cannot find pool '%s' (in datagroup list: %s)"%(rec['data'].split()[1], dg.name))

        if len(pools):
            DATAGROUP[ip] = pools


def graphme(env, output):
    global VS
    global POOLS

    dot = Digraph(engine='dot', comment='VIP')
    dot.graph_attr['rankdir'] = 'LR'
    dot.attr(label=r'\nPartition: %s\n\n '%env)
    dot.attr(fontname='helvetica')
    dot.attr(fontsize='20')
    dot.attr(labelloc='t')
    dot.attr(labeljust='l')
    dot.node_attr.update(fontname='helvetica')
    dot.node_attr.update(fontsize='12')

    dot.node('gen', label='Generated: '+time.asctime(), shape='plaintext', fontsize='10')

    colors = ['Sienna', 'Bisque', 'NavajoWhite', 'OliveDrab', 'SteelBlue', 'Lavender', 'MediumPurple', 'PaleVioletRed']


    # create nodes
    # 1/ unique pools
    for k, v in Pool.internal_unique.items():
        dot.node(str(k), '\n'.join(v))

    # 2/ pools
    for pool_env in POOLS.keys():
        for pool_name in POOLS[pool_env].keys():
            pool = POOLS[pool_env][pool_name]
            p_name = "%s_-_%s"%(pool_env, pool_name)

            # disabled pool
            if not pool.available:
                dot.node(p_name, "<<b>%s</b>>"%pool.name, style='filled', color='firebrick')
            else:
                dot.node(p_name, "<<b>%s</b>>"%pool.name)
            dot.edge(p_name, str(pool.uniqpool))


    n = randint(0, len(colors))
    for vs in VS:
        n = (n + 1)%len(colors)
        # ip node
        dot.node(vs.ipaddr, "<<b>%s</b>>"%vs.ipaddr, shape='polygon', style='filled', color=colors[n])

        # port node
        port_name = "%s_%s"%(vs.name, vs.port)
        if vs.enabled:
            dot.node(port_name, vs.port, shape='polygon', style='filled', color=colors[n])
        else:
            dot.node(port_name, vs.port, shape='polygon', style='filled', color='black', fontcolor='grey')
            

        # name node
        if vs.description is not None:
            desc = "<br align='center'/><i>%s</i>"%vs.description
        else:
            desc = ''
        if vs.enabled:
            dot.node(vs.name, "<vs:<b>&nbsp;%s</b>%s<br/><br align='left'/>snat:&nbsp;%s>"%(vs.name, desc, vs.snat), shape='polygon', style='filled', color=colors[n])
        else:
            dot.node(vs.name, "<<i>vs:<b>&nbsp;%s</b>%s<br/><br align='left'/>snat:&nbsp;%s<br/>disabled</i>>"%(vs.name, desc, vs.snat), 
                                shape='polygon', style='filled', color='black', fontcolor='grey')

        # colors for arrow
        if vs.ssl_client:
            label_ssl_client="ssl"
            color_ssl="green"
        else:
            label_ssl_client=""
            color_ssl="red"

        if vs.ssl_server:
            label_ssl_server="ssl"
        else:
            label_ssl_server=""

        # disabled vs
        if not vs.enabled:
            color_ssl="black"
            label_ssl_client="ssl/disabled"

        # ip -> port
        # port -> name
        # name -> snat
        dot.edge(vs.ipaddr, port_name)
        dot.edge(port_name, vs.name, label=label_ssl_client, color=color_ssl, fontsize='10')
        #dot.edge(vs.name, snat_name)

        # snat -> poolname
        # poolname -> poolmembers
        for pool_env, pool_name in vs.pools:
            pool = POOLS[pool_env][pool_name]
            
            p_name = "%s_-_%s"%(pool_env, pool_name)
            #dot.edge(snat_name, p_name, color=colors[n])
            dot.edge(vs.name, p_name, label=label_ssl_server, color=colors[n], fontsize='10')

    dot.render(output, format='svg', view=False)
    os.unlink(output)





def main():
    global VS
    global HOST

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-a', '--address', required=True)
    parser.add_argument('-p', '--partition', required=True)
    parser.add_argument('-o', '--output', required=True)

    args = parser.parse_args()
    Conf.mgt = ManagementRoot(args.address, USER, PASS, token=True)

    # load data group lists first (proxypass lookup)
    load_datagroup_list(args.partition)

    # load all VirtualServer objects
    for vs in list_all_vs(partition=args.partition):
        VS.append(VirtualServer(vs))


    graphme(args.partition, args.output)



if __name__ == "__main__":
    main()
