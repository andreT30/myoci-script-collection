"""Offline network relationship and mutation safety contracts."""
from dataclasses import replace
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
import oci
from test_core import CoreGateway, resource, P, C, X, R
from compartment_cleanup.model import CleanupError
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.gateway import Gateway
from compartment_cleanup.discovery import collapse_cascades
from compartment_cleanup.graph import compute_depths
try:
    from compartment_cleanup.handlers.network import Networks, RoutePreparations, NETWORK_OPERATIONS
except ImportError:
    Networks = RoutePreparations = NETWORK_OPERATIONS = None

class NetworkGateway(CoreGateway):
    def items(self,service,region,operation,params,endpoint=None):
        if service=='dns':
            self._event('items',service,region,operation,params,endpoint)
            rows=self.rows.get(operation,[])
            if isinstance(rows,Exception):raise rows
            rows=[dict(row) for row in rows if not params.get('compartment_id') or row.get('compartment_id')==params['compartment_id']]
        else:rows=super().items(service,region,operation,params,endpoint)
        return [row for row in rows
            if all(not params.get(field) or row.get(field)==params[field]
            for field in ('subnet_id','network_security_group_id','resolver_id','view_id')
            if not (field=='network_security_group_id' and operation=='list_network_security_group_security_rules'))]

class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(Networks,'Task 5B network handlers are required')
        self.g=NetworkGateway();self.h=Networks();self.prep=RoutePreparations()
    def add(self,key,kind,owner=P,metadata=None,state='AVAILABLE'):
        n=resource(key,kind,owner,state,metadata)
        self.g.add_row(n,NETWORK_OPERATIONS[kind][0]);return n
    def vcn(self):
        self.add('v','Vcn',metadata={'default_route_table_id':'rt','default_security_list_id':'sl','default_dhcp_options_id':'dh'})
        self.add('rt','RouteTable',metadata={'vcn_id':'v','route_rules':[]})
        self.add('sl','SecurityList',metadata={'vcn_id':'v'})
        self.add('dh','DhcpOptions',metadata={'vcn_id':'v'})
        self.g.rows['list_resolvers']=[{'id':'resolver','compartment_id':P,'attached_vcn_id':'v','is_protected':True,'default_view_id':'view','attached_views':[],'rules':[],'endpoints':[],'lifecycle_state':'ACTIVE'}]
        self.g.add(resource('resolver','Resolver',state='ACTIVE',metadata=self.g.rows['list_resolvers'][0]))
        self.g.add(resource('view','View',state='ACTIVE',metadata={'is_protected':True}))
        return self.h.discover(self.g,P,R)
    def by_id(self):return {n.key:n for n in self.h.discover(self.g,P,R)[0]}
    def test_defaults_and_dns_are_reciprocal_executable_cascades(self):
        nodes,edges,probes=self.vcn();by={n.key:n for n in nodes}
        self.assertFalse(by['v'].blockers)
        self.assertEqual(set(by['v'].metadata['cascade_members']),{'rt','sl','dh','resolver','view'})
        for key in ('rt','sl','dh','resolver','view'):
            self.assertEqual(by[key].action,'cascade');self.assertEqual(by[key].metadata['cascade_owner'],'v')
            self.assertTrue(by[key].metadata['cascade_verified'])
        self.assertEqual(self.h.inspect(self.g,by['v'],{P,C}).status,'present')
        self.assertTrue(all(p.status=='complete' for p in probes))
    def test_custom_subnet_before_route_table_and_vcn(self):
        self.vcn();self.add('custom','RouteTable',metadata={'vcn_id':'v','route_rules':[]})
        self.add('s','Subnet',metadata={'vcn_id':'v','route_table_id':'custom','security_list_ids':['sl'],'dhcp_options_id':'dh'})
        nodes,edges,_=self.h.discover(self.g,P,R)
        by,edges=collapse_cascades({n.key:n for n in nodes},edges);depths,blocked=compute_depths(by,edges)
        self.assertFalse(blocked);self.assertGreater(depths['s'],depths['custom']);self.assertGreater(depths['custom'],depths['v'])
    def routes(self):
        self.vcn();self.add('ig','InternetGateway',metadata={'vcn_id':'v'})
        rules=[{'network_entity_id':'ig','destination':'0.0.0.0/0','destination_type':'CIDR_BLOCK'}]
        self.g.resources['rt']=replace(self.g.resources['rt'],metadata={'vcn_id':'v','route_rules':rules})
        self.g.rows['list_route_tables'][0]['route_rules']=rules
        return self.h.discover(self.g,P,R)
    def test_route_preparation_acyclic_and_real_update_payload(self):
        nodes,edges,_=self.routes();by,edges=collapse_cascades({n.key:n for n in nodes},edges)
        depths,blocked=compute_depths(by,edges);self.assertFalse(blocked)
        n=next(n for n in nodes if n.resource_type=='RouteTablePreparation')
        self.assertGreater(depths[n.key],depths['ig']);self.assertGreater(depths['ig'],depths['v'])
        o=self.prep.inspect(self.g,n,{P,C});self.assertEqual(o.status,'present')
        self.g.responses[('network',R,'update_route_table')]=({}, {'opc-request-id':'request'})
        self.assertEqual(self.prep.submit(self.g,n,o,'attempt').status,'pending')
        params=self.g.events[-1][4];self.assertEqual(params['rt_id'],'rt');self.assertEqual(params['if_match'],'live-etag')
        self.assertEqual(oci.util.to_dict(params['update_route_table_details'])['route_rules'],[])
    def test_external_subnet_blocks_vcn_default_and_route_preparation(self):
        nodes,_,_=self.routes();prep=next(n for n in nodes if n.resource_type=='RouteTablePreparation')
        self.add('foreign','Subnet',X,{'vcn_id':'v','route_table_id':'rt'})
        by=self.by_id();self.assertTrue(by['v'].blockers);self.assertTrue(by['rt'].blockers);self.assertNotIn('foreign',by)
        self.assertEqual(self.prep.inspect(self.g,prep,{P,C}).status,'unresolved')
    def test_subnet_vnic_reverse_checks_and_order(self):
        self.vcn();self.add('s','Subnet',metadata={'vcn_id':'v'})
        self.g.add_row(resource('ip','PrivateIp',metadata={'subnet_id':'s','vnic_id':'nic'}),'list_private_ips')
        self.g.add(resource('nic','Vnic',metadata={'subnet_id':'s'}))
        nodes,edges,_=self.h.discover(self.g,P,R);n=next(n for n in nodes if n.key=='s');self.assertFalse(n.blockers)
        self.assertIn(('nic','s'),{(e.before,e.after) for e in edges})
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
        self.g.resources['nic']=replace(self.g.resources['nic'],compartment_id=X)
        self.assertTrue(self.by_id()['s'].blockers)
    def test_nsg_external_reverse_membership_and_failed_probe(self):
        self.add('n','NetworkSecurityGroup',metadata={'vcn_id':'outside'})
        self.g.rows['list_network_security_group_vnics']=[{'vnic_id':'nic','network_security_group_id':'n'}]
        self.g.add(resource('nic','Vnic',X,metadata={'nsg_ids':['n']}));self.assertTrue(self.by_id()['n'].blockers)
        self.g.rows['list_network_security_group_vnics']=CleanupError('permission failure');self.assertTrue(self.by_id()['n'].blockers)
    def test_failed_tenancy_probe_default_move_and_unsupported_child(self):
        self.vcn();self.g.rows['list_vlans']=CleanupError('permission failure');self.assertTrue(self.by_id()['v'].blockers)
        self.g.rows['list_vlans']=[];self.g.resources['sl']=replace(self.g.resources['sl'],compartment_id=X)
        self.assertTrue(self.by_id()['v'].blockers)
        self.g.resources['sl']=replace(self.g.resources['sl'],compartment_id=P)
        self.g.rows['list_vlans']=[{'id':'vlan','compartment_id':X,'vcn_id':'v','lifecycle_state':'AVAILABLE'}]
        self.assertTrue(self.by_id()['v'].blockers)
    def test_dns_external_default_view_or_endpoint_blocks(self):
        self.vcn();self.g.resources['view']=replace(self.g.resources['view'],compartment_id=X)
        self.assertTrue(self.by_id()['v'].blockers)
        self.g.resources['view']=replace(self.g.resources['view'],compartment_id=P)
        self.g.rows['list_resolver_endpoints']=[{'name':'endpoint','resolver_id':'resolver','compartment_id':P,'lifecycle_state':'ACTIVE'}]
        self.assertTrue(self.by_id()['v'].blockers)
    def test_fresh_scope_reference_etag_and_terminal_evidence(self):
        self.add('ig','InternetGateway',metadata={'vcn_id':'outside'});n=self.by_id()['ig']
        o=self.h.inspect(self.g,n,{P,C});self.assertEqual(o.status,'present')
        self.g.resources['ig']=replace(n,metadata={'vcn_id':'changed'})
        with self.assertRaises(CleanupError):self.h.submit(self.g,n,o,'attempt')
        self.g.resources['ig']=replace(n,compartment_id=X);self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'moved')
        del self.g.resources['ig'];self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
        for state,want in [('TERMINATING','pending'),('TERMINATED','deleted')]:
            self.g.add(replace(n,lifecycle_state=state));self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,want)
        self.assertFalse(any(e[0]=='write' for e in self.g.events))
    def test_registry_fixed_dispatch_no_core_type_collision(self):
        from compartment_cleanup.handlers.core import ComputeInstances
        registry=Registry({'network':self.h,'network_routes':self.prep,'compute':ComputeInstances()})
        n=registry.classify(replace(resource('x','InternetGateway',metadata={'vcn_id':'v','description':'ocid1.fake','operation':'delete_compartment'}),handler='evil',action='cascade'))
        self.assertEqual((n.handler,n.action),('network','delete'));self.assertEqual(n.metadata,{'vcn_id':'v'})
        self.assertEqual(self.h.bulk_resource_types,{})
    def test_real_dns_summary_omits_get_only_configuration(self):
        self.vcn()
        summary=oci.util.to_dict(oci.dns.models.ResolverSummary(id='resolver',compartment_id=P,
            attached_vcn_id='v',default_view_id='view',is_protected=True,lifecycle_state='ACTIVE'))
        self.g.rows['list_resolvers']=[summary]
        self.assertFalse(self.by_id()['v'].blockers)
    def test_real_resolver_endpoint_summary_requires_reciprocal_empty_inventory(self):
        self.vcn()
        self.g.resources['resolver']=replace(self.g.resources['resolver'],metadata=dict(self.g.resources['resolver'].metadata,
            endpoints=[{'name':'hidden','is_forwarding':True,'is_listening':False}]))
        self.assertTrue(self.by_id()['v'].blockers)
    def test_subnet_deletion_must_account_for_external_protected_dns_zone(self):
        self.vcn();self.add('s','Subnet',metadata={'vcn_id':'v'})
        self.g.rows['list_zones']=[{'id':'zone','compartment_id':X,'view_id':'view','scope':'PRIVATE','is_protected':True,'lifecycle_state':'ACTIVE'}]
        self.g.add(resource('zone','Zone',X,'ACTIVE',{'view_id':'view','scope':'PRIVATE','is_protected':True}))
        self.assertEqual(self.h.inspect(self.g,self.by_id()['s'],{P,C}).status,'unresolved')
    def test_unsupported_gateway_entity_is_blocked_not_guess_dispatched(self):
        self.vcn();self.g.rows['list_drg_attachments']=[{'id':'drga','compartment_id':X,'lifecycle_state':'ATTACHED','network_details':{'type':'VCN','id':'v'}}]
        self.g.add(resource('drga','DrgAttachment',X,'ATTACHED',{'network_details':{'type':'VCN','id':'v'}}))
        self.assertTrue(self.by_id()['v'].blockers)
    def test_route_preparation_changed_rules_and_etag_require_refresh(self):
        nodes,_,_=self.routes();n=next(n for n in nodes if n.resource_type=='RouteTablePreparation')
        o=self.prep.inspect(self.g,n,{P,C});self.g.etags['rt']='changed'
        with self.assertRaises(CleanupError):self.prep.submit(self.g,n,o,'attempt')
        self.g.etags.clear();self.g.resources['rt']=replace(self.g.resources['rt'],metadata={'vcn_id':'v','route_rules':[{'network_entity_id':'ig','destination':'changed'}]})
        self.assertEqual(self.prep.inspect(self.g,n,{P,C}).status,'unresolved')
    def test_sdk_readonly_probe_contracts(self):
        config={'tenancy':'ocid1.tenancy.oc1..t','region':'eu-frankfurt-1'}
        cases=[('network',oci.core.VirtualNetworkClient,'list_vlans',{'compartment_id':'c'}),
            ('network',oci.core.VirtualNetworkClient,'get_vlan',{'vlan_id':'id'}),
            ('network',oci.core.VirtualNetworkClient,'list_drg_attachments',{'compartment_id':'c'}),
            ('network',oci.core.VirtualNetworkClient,'get_drg_attachment',{'drg_attachment_id':'id'}),
            ('network',oci.core.VirtualNetworkClient,'list_network_security_group_security_rules',{'network_security_group_id':'id'}),
            ('dns',oci.dns.DnsClient,'list_resolvers',{'compartment_id':'c','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'get_resolver',{'resolver_id':'id','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'list_resolver_endpoints',{'resolver_id':'id','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'get_resolver_endpoint',{'resolver_id':'id','resolver_endpoint_name':'ep','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'get_view',{'view_id':'id','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'list_zones',{'compartment_id':'c','view_id':'id','scope':'PRIVATE'}),
            ('dns',oci.dns.DnsClient,'get_zone',{'zone_name_or_id':'ocid1.dns-zone.oc1..z','scope':'PRIVATE'})]
        for service,klass,operation,params in cases:
            with self.subTest(operation=operation):
                client=klass(config,signer=Mock(spec=oci.auth.signers.InstancePrincipalsSecurityTokenSigner));calls=[]
                client.base_client.call_api=lambda *a,**k:(calls.append((a,k)) or SimpleNamespace(data=[],headers={}))
                g=Gateway(config);g._clients[(service,'eu-frankfurt-1',None)]=client
                g.read(service,'eu-frankfurt-1',operation,params);self.assertEqual(len(calls),1)
                with self.assertRaises(CleanupError):g.write(service,'eu-frankfurt-1',operation,params)
    def test_cross_compartment_defaults_and_dns_are_preserved_identities(self):
        self.vcn()
        for key in ('rt','sl','dh','resolver','view'):
            self.g.resources[key]=replace(self.g.resources[key],compartment_id=C)
        for operation in ('list_route_tables','list_security_lists','list_dhcp_options','list_resolvers'):
            for row in self.g.rows[operation]:row['compartment_id']=C
        nodes,_,_=self.h.discover(self.g,P,R);by={n.key:n for n in nodes}
        self.assertFalse(by['v'].blockers)
        self.assertEqual(set(by['v'].metadata['cascade_members']),{'rt','sl','dh','resolver','view'})
        self.assertTrue(all(by[key].compartment_id==C for key in ('rt','sl','dh','resolver','view')))
        self.assertEqual(self.h.inspect(self.g,by['v'],{P,C}).status,'present')
    def test_integrated_compute_cascade_remaps_instance_before_subnet(self):
        from compartment_cleanup.discovery import discover
        from compartment_cleanup.handlers.core import ComputeInstances
        from simulator import Simulator
        self.vcn();self.add('s','Subnet',metadata={'vcn_id':'v','route_table_id':'rt','security_list_ids':['sl'],'dhcp_options_id':'dh'})
        self.g.add_row(resource('i','Instance',state='RUNNING'),'list_instances')
        self.g.add_row(resource('a','VnicAttachment',state='ATTACHED',metadata={'instance_id':'i','vnic_id':'nic'}),'list_vnic_attachments')
        self.g.add(resource('nic','Vnic',metadata={'subnet_id':'s','private_ip':'10.0.0.2'}))
        self.g.add_row(resource('ip','PrivateIp',state='',metadata={'vnic_id':'nic','subnet_id':'s','lifetime':'EPHEMERAL','ip_state':'ASSIGNED','ip_address':'10.0.0.2','is_primary':True}),'list_private_ips')
        parent='ocid1.compartment.oc1..parent';child='ocid1.compartment.oc1..child';outside='ocid1.compartment.oc1..outside';tenancy='ocid1.tenancy.oc1..tenancy'
        mapping={P:parent,C:child,X:outside,'tenancy':tenancy}
        self.g.tenancy_id=tenancy;self.g.compartment_links={parent:tenancy,child:parent,outside:tenancy};self.g.cleanup_scope={parent,child}
        self.g.resources={key:replace(n,compartment_id=mapping[n.compartment_id]) for key,n in self.g.resources.items()}
        for rows in self.g.rows.values():
            for row in rows:
                if row.get('compartment_id') in mapping:row['compartment_id']=mapping[row['compartment_id']]
        original=self.g.items
        def items(service,region,operation,params,endpoint=None):
            if operation in ('list_region_subscriptions','list_compartments'):return Simulator.items(self.g,service,region,operation,params,endpoint)
            if operation in ('search_resources','list_bulk_action_resource_types'):return []
            return original(service,region,operation,params,endpoint)
        self.g.items=items
        plan=discover(self.g,parent,Registry({'network':self.h,'network_routes':self.prep,'compute':ComputeInstances()}))
        self.assertFalse({key:n.blockers for key,n in plan.nodes.items() if n.blockers})
        self.assertIn(('i','s'),{(e.before,e.after) for e in plan.edges})
        self.assertGreater(plan.depths['i'],plan.depths['s']);self.assertGreater(plan.depths['s'],plan.depths['v'])
        self.assertEqual(plan.nodes['nic'].action,'cascade')
    def test_nsg_self_reference_is_owned_configuration_not_an_external_consumer(self):
        self.add('n','NetworkSecurityGroup',metadata={'vcn_id':'outside'})
        self.g.rows['list_network_security_group_security_rules']=[{'direction':'INGRESS','source_type':'NETWORK_SECURITY_GROUP','source':'n'}]
        n=self.by_id()['n'];self.assertFalse(n.blockers)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
    def test_completed_route_preparation_does_not_survive_previous_plan_refresh(self):
        from compartment_cleanup.discovery import discover
        from simulator import Simulator
        self.routes()
        parent='ocid1.compartment.oc1..parent';child='ocid1.compartment.oc1..child';outside='ocid1.compartment.oc1..outside';tenancy='ocid1.tenancy.oc1..tenancy'
        mapping={P:parent,C:child,X:outside,'tenancy':tenancy}
        self.g.tenancy_id=tenancy;self.g.compartment_links={parent:tenancy,child:parent,outside:tenancy};self.g.cleanup_scope={parent,child}
        self.g.resources={key:replace(n,compartment_id=mapping[n.compartment_id]) for key,n in self.g.resources.items()}
        for rows in self.g.rows.values():
            for row in rows:
                if row.get('compartment_id') in mapping:row['compartment_id']=mapping[row['compartment_id']]
        original=self.g.items
        def items(service,region,operation,params,endpoint=None):
            if operation in ('list_region_subscriptions','list_compartments'):return Simulator.items(self.g,service,region,operation,params,endpoint)
            if operation in ('search_resources','list_bulk_action_resource_types'):return []
            return original(service,region,operation,params,endpoint)
        self.g.items=items;registry=Registry({'network':self.h,'network_routes':self.prep})
        previous=discover(self.g,parent,registry)
        prep=next(n for n in previous.nodes.values() if n.resource_type=='RouteTablePreparation')
        self.g.resources['rt']=replace(self.g.resources['rt'],metadata={'vcn_id':'v','route_rules':[]})
        self.g.rows['list_route_tables'][0]['route_rules']=[]
        self.assertEqual(self.prep.inspect(self.g,prep,{parent,child}).status,'deleted')
        current=discover(self.g,parent,registry,previous)
        self.assertNotIn(prep.key,current.nodes)
        self.assertFalse(current.nodes['v'].blockers)
        self.assertEqual(current.nodes['rt'].metadata['route_rules'],[])
    def test_default_routes_without_verified_preparation_block_discovery(self):
        for target in ('ocid1.drg.oc1..unsupported','ip'):
            with self.subTest(target=target):
                self.g=NetworkGateway();self.vcn()
                if target=='ip':self.g.add(resource('ip','PrivateIp',state='',metadata={'subnet_id':'s','vnic_id':'nic','lifetime':'EPHEMERAL','ip_state':'ASSIGNED'}))
                rules=[{'network_entity_id':target,'destination':'0.0.0.0/0','destination_type':'CIDR_BLOCK'}]
                self.g.resources['rt']=replace(self.g.resources['rt'],metadata={'vcn_id':'v','route_rules':rules})
                self.g.rows['list_route_tables'][0]['route_rules']=rules
                nodes,edges,_=self.h.discover(self.g,P,R);by={n.key:n for n in nodes}
                self.assertTrue(by['rt'].blockers)
                self.assertTrue(by['v'].blockers)
                self.assertEqual(by['v'].action,'unresolved')
                by,edges=collapse_cascades(by,edges);depths,blocked=compute_depths(by,edges)
                self.assertNotIn('v',depths);self.assertIn('v',blocked)
                self.assertFalse(any(n.resource_type=='RouteTablePreparation' for n in nodes))
    def test_foreign_resolver_requires_explicit_valid_reverse_view_references(self):
        for value in (None,'missing',[{}],[{'view_id':None}],[{'view_id':''}],[]):
            with self.subTest(attached_views=value):
                self.g=NetworkGateway();self.vcn()
                row={'id':'foreign-resolver','compartment_id':X,'attached_vcn_id':'outside-vcn',
                    'default_view_id':'other-view','is_protected':True,'lifecycle_state':'ACTIVE','rules':[],'endpoints':[]}
                if value!='missing':row['attached_views']=value
                summary=oci.util.to_dict(oci.dns.models.ResolverSummary(id=row['id'],compartment_id=X,
                    attached_vcn_id=row['attached_vcn_id'],default_view_id=row['default_view_id'],is_protected=True,lifecycle_state='ACTIVE'))
                self.g.rows['list_resolvers'].append(summary)
                self.g.add(resource(row['id'],'Resolver',X,'ACTIVE',row))
                vcn=self.by_id()['v']
                if value==[]:
                    self.assertFalse(vcn.blockers);self.assertEqual(self.h.inspect(self.g,vcn,{P,C}).status,'present')
                else:
                    self.assertTrue(vcn.blockers);self.assertEqual(vcn.action,'unresolved')
    def test_sdk_exact_parameters(self):
        config={'tenancy':'ocid1.tenancy.oc1..t','region':'eu-frankfurt-1'}
        client=oci.core.VirtualNetworkClient(config,signer=Mock(spec=oci.auth.signers.InstancePrincipalsSecurityTokenSigner));calls=[]
        client.base_client.call_api=lambda *a,**k:(calls.append((a,k)) or SimpleNamespace(data=[],headers={}))
        g=Gateway(config);g._clients[('network','eu-frankfurt-1',None)]=client
        for kind,(listing,get,delete,param) in NETWORK_OPERATIONS.items():
            g.read('network','eu-frankfurt-1',listing,{'compartment_id':'c'})
            g.read('network','eu-frankfurt-1',get,{param:'id'})
            g.write('network','eu-frankfurt-1',delete,{param:'id','if_match':'etag'})
        g.write('network','eu-frankfurt-1','update_route_table',{'rt_id':'rt','if_match':'etag','update_route_table_details':oci.core.models.UpdateRouteTableDetails(route_rules=[])})
        self.assertEqual(oci.util.to_dict(calls[-1][1]['body'])['route_rules'],[])
        self.assertEqual(calls[-1][1]['header_params']['if-match'],'etag')

if __name__=='__main__':unittest.main()
