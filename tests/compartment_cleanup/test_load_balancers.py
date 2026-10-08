"""Offline LB/NLB scope, configuration ownership and async proof contracts."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
import oci
from test_core import CoreGateway, resource, P, C, X, R
from compartment_cleanup.model import CleanupError, child_key
from compartment_cleanup.handlers.base import Registry
from compartment_cleanup.gateway import Gateway, GatewayError
from compartment_cleanup.discovery import collapse_cascades
try:
    from compartment_cleanup.handlers.load_balancers import LoadBalancers
except ImportError:
    LoadBalancers = None

LB = 'ocid1.loadbalancer.oc1.region.lb'
NLB = 'ocid1.networkloadbalancer.oc1.region.nlb'


def payload(kind):
    row = {'network_security_group_ids':['nsg'], 'listeners':{'https':{'name':'https',
           'default_backend_set_name':'pool'}}, 'backend_sets':{'pool':{'name':'pool',
           'backends':[{'name':'backend','ip_address':'10.0.0.2','port':443}]}}, 'ip_addresses':[]}
    if kind == 'LoadBalancer':
        row.update(subnet_ids=['subnet'], hostnames={}, certificates={}, path_route_sets={},
                   rule_sets={}, routing_policies={}, ssl_cipher_suites={}, is_delete_protection_enabled=False)
    else:
        row['subnet_id']='subnet'
    return row


class LoadBalancerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(LoadBalancers, 'Task 5C handlers are required')
        self.h=LoadBalancers();self.g=CoreGateway()
        self.g.add(resource('subnet','Subnet',metadata={'vcn_id':'vcn'}))
        self.g.add(resource('nsg','NetworkSecurityGroup',metadata={'vcn_id':'vcn'}))

    def add(self, kind='LoadBalancer', metadata=None, owner=P):
        key=LB if kind=='LoadBalancer' else NLB
        n=resource(key,kind,owner,'ACTIVE',payload(kind) if metadata is None else metadata)
        self.g.add_row(n,'list_load_balancers' if kind=='LoadBalancer' else 'list_network_load_balancers')
        return n

    def discovered(self,key=LB):
        return next(n for n in self.h.discover(self.g,P,R)[0] if n.key==key)

    def test_configuration_cascades_references_are_preserved_without_secrets(self):
        row=payload('LoadBalancer');row['certificates']={'copy':{'certificate_name':'copy',
          'public_certificate':'fixture-secret-pem','private_key':'fixture-secret-key'}}
        row['listeners']['https']['ssl_configuration']={'certificate_name':'copy','certificate_ids':['cert'],
          'trusted_certificate_authority_ids':['ca']}
        self.g.add(resource('cert','Certificate',X,'ACTIVE'));self.g.add(resource('ca','CertificateAuthority',X,'ACTIVE'))
        self.add(metadata=row)
        nodes,edges,probes=self.h.discover(self.g,P,R);by={n.key:n for n in nodes};owner=by[LB]
        self.assertFalse(owner.blockers)
        self.assertEqual(owner.metadata['certificate_ids'],['cert'])
        self.assertEqual(owner.metadata['trusted_certificate_authority_ids'],['ca'])
        self.assertEqual(len(owner.metadata['cascade_members']),3)
        self.assertNotIn('fixture-secret',json.dumps([n.metadata for n in nodes]))
        collapsed,_=collapse_cascades(by,edges)
        self.assertTrue(all(collapsed[k].action=='cascade' for k in owner.metadata['cascade_members']))
        self.assertEqual(self.h.inspect(self.g,owner,{P,C}).status,'present')
        self.assertTrue(all(p.status=='complete' for p in probes))
        self.assertTrue({'subnet_ids','network_security_group_ids','certificate_ids'} <= set(self.h.retained_reference_fields))
        classified=Registry({self.h.name:self.h}).classify(replace(owner,handler='evil',metadata=dict(owner.metadata,private_key='secret')))
        self.assertNotIn('private_key',classified.metadata)
        self.assertEqual(self.h.bulk_resource_types,{})

    def test_both_subnet_shapes_and_fresh_nsg_ownership(self):
        self.add();self.add('NetworkLoadBalancer')
        nodes,edges,_=self.h.discover(self.g,P,R)
        self.assertTrue({(LB,'subnet'),(NLB,'subnet'),(LB,'nsg'),(NLB,'nsg')} <= {(e.before,e.after) for e in edges})
        n=self.discovered(NLB);self.assertEqual(n.metadata['subnet_id'],'subnet')
        self.g.resources['nsg']=replace(self.g.resources['nsg'],compartment_id=X)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_external_subnet_blocks_even_with_empty_endpoint_inventory(self):
        self.g.resources['subnet']=replace(self.g.resources['subnet'],compartment_id=X)
        self.g.resources['nsg']=replace(self.g.resources['nsg'],compartment_id=X)
        for kind,key,field,expected in [('LoadBalancer',LB,'subnet_ids',['subnet']),('NetworkLoadBalancer',NLB,'subnet_id','subnet')]:
            with self.subTest(kind=kind):
                self.add(kind);n=self.discovered(key);self.assertTrue(n.blockers)
                self.assertEqual(n.metadata[field],expected)
                self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_external_nsg_reference_is_retained_with_subnet_in_scope(self):
        self.g.resources['nsg']=replace(self.g.resources['nsg'],compartment_id=X)
        self.add();n=self.discovered();self.assertFalse(n.blockers)
        self.assertEqual(n.metadata['network_security_group_ids'],['nsg'])
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')

    def test_reserved_public_ip_is_live_retained_reference_never_cascade(self):
        row=payload('LoadBalancer');row['ip_addresses']=[{'ip_address':'198.51.100.1','is_public':True,'reserved_ip':{'id':'rip'}}]
        self.g.add(resource('rip','PublicIp',X,metadata={'lifetime':'RESERVED','private_ip_id':'pip'}))
        self.g.add(resource('pip','PrivateIp',metadata={'vnic_id':'vnic','subnet_id':'subnet'}))
        self.g.add(resource('vnic','Vnic',metadata={'subnet_id':'subnet','nsg_ids':['nsg']}))
        self.add(metadata=row);n=self.discovered();self.assertFalse(n.blockers)
        self.assertEqual(n.metadata['reserved_public_ip_ids'],['rip'])
        self.assertNotIn('rip',n.metadata['cascade_members'])
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
        self.g.resources['rip']=replace(self.g.resources['rip'],metadata={'lifetime':'EPHEMERAL'})
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_external_managed_ips_and_unknown_configuration_are_blocked(self):
        for change in ({'ip_addresses':[{'ip_address':'10.0.0.1','is_public':False}]},
                       {'unknown_children':{'external':{'id':'outside'}}}):
            with self.subTest(change=change):
                self.g=CoreGateway();self.g.add(resource('subnet','Subnet'));self.g.add(resource('nsg','NetworkSecurityGroup'))
                self.g.resources['subnet']=replace(self.g.resources['subnet'],compartment_id=X)
                row=payload('LoadBalancer');row.update(change);self.add(metadata=row)
                self.assertTrue(self.discovered().blockers)
                self.assertEqual(self.h.inspect(self.g,self.discovered(),{P,C}).status,'unresolved')
                self.assertFalse(any(e[0]=='write' for e in self.g.events))

    def test_inherited_managed_ip_scope_is_proved_from_fresh_subnet(self):
        row=payload('LoadBalancer');row['ip_addresses']=[{'ip_address':'10.0.0.1','is_public':False}]
        self.add(metadata=row);n=self.discovered();self.assertFalse(n.blockers)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
        self.g.resources['subnet']=replace(self.g.resources['subnet'],compartment_id=X)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_backend_target_is_preserved_reference_not_owned_configuration(self):
        row=payload('NetworkLoadBalancer');row['backend_sets']['pool']['backends'][0]['target_id']='ocid1.unknown.oc1.region.external'
        self.add('NetworkLoadBalancer',row);n=self.discovered(NLB)
        self.assertEqual(n.metadata['backend_target_ids'],['ocid1.unknown.oc1.region.external'])
        self.assertNotIn('ocid1.unknown.oc1.region.external',n.metadata['cascade_members'])
        # NLB target cascade behavior is not documented for arbitrary target types.
        self.assertTrue(n.blockers)

    def test_typed_nlb_instance_and_private_ip_targets_are_retained(self):
        for key,kind in [('ocid1.instance.oc1.region.external','Instance'),('ocid1.privateip.oc1.region.external','PrivateIp')]:
            with self.subTest(kind=kind):
                self.g=CoreGateway();self.g.add(resource('subnet','Subnet'));self.g.add(resource('nsg','NetworkSecurityGroup'))
                self.g.add(resource(key,kind,X,'RUNNING' if kind=='Instance' else '',{'subnet_id':'external-subnet'}))
                row=payload('NetworkLoadBalancer');row['backend_sets']['pool']['backends'][0]['target_id']=key
                self.add('NetworkLoadBalancer',row);n=self.discovered(NLB)
                self.assertFalse(n.blockers)
                self.assertEqual(n.metadata['backend_target_ids'],[key])
                self.assertNotIn(key,n.metadata['cascade_members'])
                self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')

    def test_relationship_and_configuration_drift_prevent_submission(self):
        self.add();n=self.discovered();o=self.h.inspect(self.g,n,{P,C});self.assertEqual(o.status,'present')
        row=deepcopy(self.g.resources[LB].metadata);row['listeners']['new']={'name':'new','default_backend_set_name':'pool'}
        self.g.resources[LB]=replace(self.g.resources[LB],metadata=row)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
        with self.assertRaises(CleanupError):self.h.submit(self.g,n,o,'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))

    def test_denied_reference_keeps_safe_declared_ids_in_report(self):
        row=payload('LoadBalancer');row['listeners']['https']['ssl_configuration']={'certificate_ids':['cert']}
        self.add(metadata=row);self.g.deny('certificates',R,'get_certificate',403)
        n=self.discovered();self.assertTrue(n.blockers)
        self.assertEqual(n.metadata['certificate_ids'],['cert'])
        self.assertEqual(n.metadata['subnet_ids'],['subnet'])
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_lost_response_and_404_do_not_prove_deletion(self):
        self.add();n=self.discovered();o=self.h.inspect(self.g,n,{P,C})
        self.g.responses[('load_balancer',R,'delete_load_balancer')]=GatewayError('load_balancer','delete_load_balancer')
        with self.assertRaises(CleanupError):self.h.submit(self.g,n,o,'attempt')
        self.g.deny('load_balancer',R,'get_load_balancer',404)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')

    def test_positive_terminal_and_pending_states_with_movement(self):
        self.add();n=self.discovered()
        for state,status in [('DELETING','pending'),('DELETED','deleted'),('FAILED','unresolved')]:
            self.g.resources[LB]=replace(self.g.resources[LB],lifecycle_state=state)
            self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,status)
        self.g.resources[LB]=replace(self.g.resources[LB],compartment_id=X,lifecycle_state='DELETED')
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'moved')

    def test_async_submission_records_work_request_header_not_trace(self):
        for kind,key,service,operation,param in [('LoadBalancer',LB,'load_balancer','delete_load_balancer','load_balancer_id'),
          ('NetworkLoadBalancer',NLB,'network_load_balancer','delete_network_load_balancer','network_load_balancer_id')]:
            with self.subTest(kind=kind):
                self.add(kind);n=self.discovered(key);o=self.h.inspect(self.g,n,{P,C})
                self.g.responses[(service,R,operation)]=(None,{'opc-request-id':'trace','opc-work-request-id':'work'})
                result=self.h.submit(self.g,n,o,'attempt')
                self.assertEqual((result.status,result.request_id),('pending','work'))
                self.assertEqual([e for e in self.g.events if e[0]=='write'][-1][4],{param:key,'if_match':'live-etag'})
                self.g.responses[(service,R,operation)]=(None,{'opc-workrequest-id':'defensive'})
                self.assertEqual(self.h.submit(self.g,n,o,'attempt').request_id,'defensive')
                self.g.responses[(service,R,operation)]=(None,{'opc-request-id':'trace'})
                self.assertIsNone(self.h.submit(self.g,n,o,'attempt').request_id)

    def work(self,kind='LoadBalancer',**updates):
        self.add(kind);key=LB if kind=='LoadBalancer' else NLB;n=self.discovered(key)
        if kind=='LoadBalancer':
            work={'id':'work','compartment_id':P,'load_balancer_id':key,'type':'DeleteLoadBalancer','lifecycle_state':'SUCCEEDED','error_details':[]}
        else:
            work={'id':'work','compartment_id':P,'operation_type':'DELETE_NETWORK_LOAD_BALANCER','status':'SUCCEEDED',
                  'resources':[{'identifier':key,'entity_type':'networkloadbalancer','action_type':'DELETED'}]}
        work.update(updates);self.g.work_requests['work']=work
        return self.h.inspect_work_request(self.g,n,'work',{P,C})

    def test_exact_lb_delete_work_request_positive_proof(self):
        self.assertEqual(self.work().status,'deleted')
        for fields in ({'type':'DeleteListener'},{'id':'wrong'},{'load_balancer_id':NLB},{'compartment_id':X},
                       {'error_details':[{'message':'failure'}]},{'error_details':None}):
            self.assertEqual(self.work(**fields).status,'unresolved')
        self.assertEqual(self.work(lifecycle_state='ACCEPTED').status,'pending')
        self.assertEqual(self.work(lifecycle_state='FAILED').status,'unresolved')
        n=replace(self.discovered(),key=NLB)
        self.g.work_requests['work']={'id':'work','compartment_id':P,'load_balancer_id':NLB,'type':'DeleteLoadBalancer','lifecycle_state':'SUCCEEDED','error_details':[]}
        self.assertEqual(self.h.inspect_work_request(self.g,n,'work',{P,C}).status,'unresolved')

    def test_nlb_work_request_checks_deletion_resource_and_all_error_pages(self):
        self.assertEqual(self.work('NetworkLoadBalancer').status,'deleted')
        for fields in ({'operation_type':'CREATE_NETWORK_LOAD_BALANCER'}, {'compartment_id':X},
          {'resources':[{'identifier':LB,'entity_type':'networkloadbalancer','action_type':'DELETED'}]},
          {'resources':[{'identifier':'ocid1.instance.oc1.region.other','entity_type':'instance','action_type':'DELETED'}]},
          {'resources':[{'identifier':NLB,'entity_type':'networkloadbalancer','action_type':'RELATED'}]}):
            self.assertEqual(self.work('NetworkLoadBalancer',**fields).status,'unresolved')
        self.g.rows['list_work_request_errors']=[{'compartment_id':P,'code':'failure'}]
        self.assertEqual(self.work('NetworkLoadBalancer').status,'unresolved')
        self.g.rows['list_work_request_errors']=GatewayError('network_load_balancer','list_work_request_errors',403)
        self.assertEqual(self.work('NetworkLoadBalancer').status,'unresolved')

    def test_nlb_pending_work_request_never_requires_future_deleted_resource(self):
        self.assertEqual(self.work('NetworkLoadBalancer', status='ACCEPTED', resources=[]).status,'pending')
        self.assertEqual(self.work('NetworkLoadBalancer', status='IN_PROGRESS', resources=[
            {'identifier':NLB,'entity_type':'networkloadbalancer','action_type':'IN_PROGRESS'}]).status,'pending')

    def test_network_graph_accepts_known_lb_and_nlb_consumers_before_subnet(self):
        from test_network import NetworkTests
        fixture=NetworkTests();fixture.setUp();fixture.vcn()
        fixture.add('subnet','Subnet',metadata={'vcn_id':'v','route_table_id':'rt','security_list_ids':['sl'],'dhcp_options_id':'dh'})
        fixture.add('nsg','NetworkSecurityGroup',metadata={'vcn_id':'v'})
        self.g=fixture.g;self.add();self.add('NetworkLoadBalancer')
        nodes,edges,_=fixture.h.discover(self.g,P,R);by={n.key:n for n in nodes}
        self.assertFalse(by['subnet'].blockers)
        self.assertFalse(by['nsg'].blockers)
        self.assertTrue({(LB,'subnet'),(NLB,'subnet'),(LB,'nsg'),(NLB,'nsg')} <= {(e.before,e.after) for e in edges})
        self.assertEqual(fixture.h.inspect(self.g,by['subnet'],{P,C}).status,'unresolved')

    def test_ca_bundle_references_use_the_typed_certificate_service_getter(self):
        row=payload('LoadBalancer');key='ocid1.cabundle.oc1.region.bundle'
        row['listeners']['https']['ssl_configuration']={'trusted_certificate_authority_ids':[key]}
        self.g.add(resource(key,'CaBundle',X,'ACTIVE'));self.add(metadata=row)
        n=self.discovered();self.assertFalse(n.blockers)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
        self.assertTrue(any(e[3]=='get_ca_bundle' and e[4]=={'ca_bundle_id':key} for e in self.g.events if e[0]=='read'))

    def test_unknown_nested_independent_resource_and_bad_child_identity_block(self):
        row=payload('LoadBalancer');row['listeners']['https']['consumer_id']='outside'
        self.add(metadata=row);self.assertTrue(self.discovered().blockers)
        self.g=CoreGateway();self.g.add(resource('subnet','Subnet'));self.g.add(resource('nsg','NetworkSecurityGroup'));self.add()
        child=next(n for n in self.h.discover(self.g,P,R)[0] if n.action=='cascade')
        self.g.resources[LB]=replace(self.g.resources[LB],lifecycle_state='DELETED')
        self.assertEqual(self.h.inspect(self.g,replace(child,key='fake'),{P,C}).status,'unresolved')

    def test_nested_unknown_owned_configuration_and_wrong_shapes_block(self):
        unknown={'id':'ocid1.unknown.oc1..outside','compartment_id':X}
        for kind,field,name,nested_key,value in [
            ('LoadBalancer','backend_sets','pool','health_checker',unknown),
            ('LoadBalancer','backend_sets','pool','session_persistence_configuration',unknown),
            ('LoadBalancer','backend_sets','pool','lb_cookie_session_persistence_configuration',unknown),
            ('LoadBalancer','listeners','https','connection_configuration',unknown),
            ('LoadBalancer','path_route_sets','paths','path_routes',[{'path':'/','path_match_type':unknown}]),
            ('LoadBalancer','routing_policies','routing','rules',[{'name':'rule','condition':'true','actions':[unknown]}]),
            ('LoadBalancer','rule_sets','rules','items',[{'action':'ALLOW','conditions':[unknown]}]),
            ('LoadBalancer','backend_sets','pool','health_checker',{'port':{'id':'outside'}}),
            ('NetworkLoadBalancer','backend_sets','pool','health_checker',{'dns':unknown}),
        ]:
            with self.subTest(kind=kind,nested=nested_key):
                self.g=CoreGateway();self.g.add(resource('subnet','Subnet'));self.g.add(resource('nsg','NetworkSecurityGroup'))
                row=payload(kind);row.setdefault(field,{}).setdefault(name,{'name':name})[nested_key]=value
                self.add(kind,row);n=self.discovered(LB if kind=='LoadBalancer' else NLB)
                self.assertTrue(n.blockers)
                self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'unresolved')
                self.assertFalse(any(e[0]=='write' for e in self.g.events))

    def test_sdk_typed_nested_configuration_is_accepted_without_content_leaks(self):
        row=payload('LoadBalancer')
        row['backend_sets']['pool']['health_checker']=oci.util.to_dict(oci.load_balancer.models.HealthChecker(protocol='HTTP',port=80,response_body_regex='fixture-secret-regex'))
        row['backend_sets']['pool']['session_persistence_configuration']=oci.util.to_dict(oci.load_balancer.models.SessionPersistenceConfigurationDetails(cookie_name='session',disable_fallback=True))
        row['listeners']['https']['connection_configuration']=oci.util.to_dict(oci.load_balancer.models.ConnectionConfiguration(idle_timeout=60))
        row['path_route_sets']={'paths':oci.util.to_dict(oci.load_balancer.models.PathRouteSet(name='paths',path_routes=[oci.load_balancer.models.PathRoute(path='/',path_match_type=oci.load_balancer.models.PathMatchType(match_type='EXACT_MATCH'),backend_set_name='pool')]))}
        row['rule_sets']={'headers':oci.util.to_dict(oci.load_balancer.models.RuleSet(name='headers',items=[oci.load_balancer.models.AddHttpRequestHeaderRule(action='ADD_HTTP_REQUEST_HEADER',header='test',value='fixture-secret-header')]))}
        row['routing_policies']={'routing':oci.util.to_dict(oci.load_balancer.models.RoutingPolicy(name='routing',condition_language_version='V1',rules=[oci.load_balancer.models.RoutingRule(name='route',condition='true',actions=[oci.load_balancer.models.ForwardToBackendSet(name='FORWARD_TO_BACKENDSET',backend_set_name='pool')])]))}
        self.add(metadata=row);n=self.discovered();self.assertFalse(n.blockers)
        self.assertEqual(self.h.inspect(self.g,n,{P,C}).status,'present')
        self.assertNotIn('fixture-secret',json.dumps(n.metadata))
        self.g=CoreGateway();self.g.add(resource('subnet','Subnet'));self.g.add(resource('nsg','NetworkSecurityGroup'))
        row=payload('NetworkLoadBalancer');row['backend_sets']['pool']['health_checker']=oci.util.to_dict(oci.network_load_balancer.models.HealthChecker(protocol='DNS',dns=oci.network_load_balancer.models.DnsHealthCheckerDetails(domain_name='example.test',transport_protocol='UDP',rcodes=['NOERROR'])))
        self.add('NetworkLoadBalancer',row);self.assertFalse(self.discovered(NLB).blockers)

    def test_configuration_children_have_no_independent_delete(self):
        self.add();nodes,_,_=self.h.discover(self.g,P,R)
        child=next(n for n in nodes if n.action=='cascade')
        self.assertEqual(self.h.inspect(self.g,child,{P,C}).status,'present')
        with self.assertRaises(CleanupError):self.h.submit(self.g,child,self.h.inspect(self.g,child,{P,C}),'attempt')
        self.assertFalse(any(e[0]=='write' for e in self.g.events))


class SDKBoundaryTests(unittest.TestCase):
    def test_real_sdk_models_and_conditional_delete_wire_contracts(self):
        config={'tenancy':'ocid1.tenancy.oc1..t','region':'eu-frankfurt-1'}
        for kind,key,service,model,client_class,listing,get,delete,param in [
            ('LoadBalancer',LB,'load_balancer',oci.load_balancer.models.LoadBalancer,oci.load_balancer.LoadBalancerClient,
             'list_load_balancers','get_load_balancer','delete_load_balancer','load_balancer_id'),
            ('NetworkLoadBalancer',NLB,'network_load_balancer',oci.network_load_balancer.models.NetworkLoadBalancer,oci.network_load_balancer.NetworkLoadBalancerClient,
             'list_network_load_balancers','get_network_load_balancer','delete_network_load_balancer','network_load_balancer_id')]:
            client=client_class(config,signer=Mock(spec=oci.auth.signers.InstancePrincipalsSecurityTokenSigner));calls=[]
            client.base_client.call_api=lambda *a,**k:(calls.append((a,k)) or SimpleNamespace(data=None,headers={'opc-work-request-id':'work','opc-request-id':'trace'}))
            g=Gateway(config);g._clients[(service,config['region'],None)]=client
            g.read(service,config['region'],listing,{'compartment_id':P})
            g.read(service,config['region'],get,{param:key})
            result=g.write(service,config['region'],delete,{param:key,'if_match':'etag'})
            self.assertEqual(result[1]['opc-work-request-id'],'work')
            self.assertEqual(calls[-1][1]['header_params']['if-match'],'etag')
            row=oci.util.to_dict(model(id=key,compartment_id=P,lifecycle_state='ACTIVE',**payload(kind)))
            fixture=LoadBalancerTests();fixture.setUp();fixture.add(kind,row)
            n=fixture.discovered(key);self.assertFalse(n.blockers)
            self.assertEqual(fixture.h.inspect(fixture.g,n,{P,C}).status,'present')

    def test_nlb_error_inventory_is_read_only_and_paginates(self):
        g=Gateway({'tenancy':'tenancy','region':R});fake=SimpleNamespace(list_work_request_errors=Mock(side_effect=[
          SimpleNamespace(data=oci.network_load_balancer.models.WorkRequestErrorCollection(items=[]),headers={'opc-next-page':'next'}),
          SimpleNamespace(data=oci.network_load_balancer.models.WorkRequestErrorCollection(items=[oci.network_load_balancer.models.WorkRequestError(code='failure')]),headers={})]))
        g._clients[('network_load_balancer',R,None)]=fake
        errors=g.items('network_load_balancer',R,'list_work_request_errors',{'work_request_id':'work','compartment_id':P})
        self.assertEqual(errors[0]['code'],'failure')
        self.assertEqual(fake.list_work_request_errors.call_args.kwargs['page'],'next')
        with self.assertRaises(CleanupError):g.write('network_load_balancer',R,'list_work_request_errors',{})
