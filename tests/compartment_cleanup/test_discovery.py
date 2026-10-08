"""Offline inventory contracts: authoritative scope, coverage, and relationships."""
from dataclasses import replace
import unittest
import oci
from compartment_cleanup.model import Node, Edge, Probe, Observation, CleanupError, plan_to_dict, plan_from_dict
from compartment_cleanup.graph import validate_scope
from compartment_cleanup.discovery import discover, merge_nodes, collapse_cascades, compare_plan
from compartment_cleanup.handlers.base import Handler, Registry
from simulator import Simulator

P = 'ocid1.compartment.oc1..parent'
C = 'ocid1.compartment.oc1..child'
T = 'ocid1.tenancy.oc1..tenancy'


def node(key, compartment=P, region='r1', metadata=None, kind='Thing', action='delete'):
    return Node(key, kind, region, compartment, key, 'ACTIVE', 'things', action, metadata or {})


class Things(Handler):
    name = 'things'
    resource_types = ('Thing',)
    action = 'delete'
    metadata_keys = ('target_id', 'cascade_owner', 'cascade_verified', 'cascade_members', 'scheduled_at', 'bulk_label')
    reference_fields = ('target_id',)
    bulk_resource_types = {'Thing': 'thing-bulk'}

    def discover(self, gateway, compartment_id, region):
        return ([n for n in gateway.resources.values() if n.compartment_id == compartment_id and n.region == region], [],
                [Probe(self.name, region, compartment_id, 'complete', '')])

    def inspect(self, gateway, n, scope):
        if n.key not in gateway.resources:
            return Observation('unresolved', n.compartment_id, '', None, None, 'Read not authorized or not found')
        live = gateway.resources[n.key]
        status = 'moved' if live.compartment_id not in scope else ('pending' if live.lifecycle_state == 'PENDING_DELETION' else 'present')
        return Observation(status, live.compartment_id, live.lifecycle_state, live.metadata.get('scheduled_at'), None, '')

    def bulk_metadata(self, n, required):
        return {'label': n.metadata['bulk_label']} if 'bulk_label' in n.metadata else {}


class Inventory(Simulator):
    def __init__(self):
        super().__init__(T, 'r1', {P:T, C:P})
        self.regions = ['r1', 'r2']
        self.search = []
        self.catalog = [{'name':'thing-bulk', 'metadata_keys':['label']}, {'name':'Mystery', 'metadata_keys':[]}]

    def items(self, service, region, operation, params, endpoint=None):
        if operation == 'search_resources':
            self._event('items', service, region, operation, params, endpoint)
            details = params['search_details']
            if not isinstance(details, oci.resource_search.models.StructuredSearchDetails):
                raise AssertionError('Search must use real SDK model')
            compartment = C if C in details.query else P
            return [dict(x) for x in self.search if x.get('compartment_id') == compartment]
        if operation == 'list_bulk_action_resource_types':
            self._event('items', service, region, operation, params, endpoint)
            if params != {'bulk_action_type':'BULK_DELETE_RESOURCES'}:
                raise AssertionError('wrong bulk catalog arguments')
            return list(self.catalog)
        return super().items(service, region, operation, params, endpoint)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.g = Inventory()
        self.registry = Registry({'things': Things()})

    def test_search_duplicates_and_service_omissions_preserve_scope_and_metadata(self):
        self.g.search = [dict(identifier='global', resource_type='Mystery', compartment_id=P, display_name='g', lifecycle_state='ACTIVE',
                              freeform_tags={'secret':'do not persist'}, endpoint='https://evil', target_id=C)]
        self.g.add(node('service-only', C, 'r2', {'bulk_label':'exact', 'target_id':'dependency', 'secret_content':'hidden'}))
        self.g.add(node('dependency', C, 'r2'))
        plan = discover(self.g, P, self.registry)
        self.assertEqual(set(plan.nodes), {P,C,'global','service-only','dependency'})
        self.assertEqual(plan.nodes[P].compartment_id, T)
        self.assertEqual(plan.nodes[P].action, 'retain')
        self.assertEqual(plan.nodes[C].compartment_id, P)
        self.assertEqual(plan.nodes['service-only'].metadata['bulk_metadata'], {'label':'exact'})
        self.assertEqual(plan.bulk_types['thing-bulk'], ('label',))
        self.assertNotIn('secret_content', str(plan_to_dict(plan)))
        self.assertNotIn('https://evil', str(plan_to_dict(plan)))
        self.assertNotIn('freeform_tags', str(plan_to_dict(plan)))
        self.assertTrue(plan.nodes['global'].blockers)
        self.assertEqual(plan.nodes['global'].action, 'unresolved')
        self.assertIn(Edge('service-only','dependency','Typed field: target_id'), plan.edges)
        self.assertIn(Edge('service-only',C,'Resource belongs to compartment'), plan.edges)
        self.assertIn(Edge(C,P,'Child compartment belongs to parent'), plan.edges)
        queries = [e[4]['search_details'].query for e in self.g.events if e[3] == 'search_resources']
        self.assertEqual(sorted(queries), sorted([f"query all resources where compartmentId = '{c}'" for c in (P,C) for _ in range(2)]))
        validate_scope(plan_from_dict(plan_to_dict(plan)), P)

    def test_merge_authoritative_service_identity_wins_and_conflicts_block(self):
        merged = merge_nodes([node('x', region='r1', action='unresolved'), node('x', region='r2', action='unresolved')], [node('x',C,'r2')])
        self.assertEqual(merged['x'].compartment_id,C)
        self.assertEqual(merged['x'].region,'r2')
        conflict = merge_nodes([], [node('x'), node('x',C)])['x']
        self.assertEqual(conflict.action,'unresolved')

    def test_edited_handler_and_action_never_select_operation(self):
        n = replace(node('x'), handler='delete_vault', action='schedule')
        self.assertIs(self.registry.handler_for(n), self.registry.handlers['things'])
        self.assertEqual(self.registry.classify(n).handler, 'things')
        self.assertEqual(self.registry.classify(n).action,'delete')
        self.assertIsNone(self.registry.handler_for(node('unknown', kind='Mystery')))

    def test_failed_probe_blocks_child_and_parent(self):
        class Denied(Things):
            def discover(self, gateway, compartment_id, region):
                if compartment_id == C and region == 'r2':
                    raise CleanupError('secret raw exception')
                return super().discover(gateway, compartment_id, region)
        plan = discover(self.g,P,Registry({'things':Denied()}))
        self.assertTrue(plan.nodes[C].blockers)
        self.assertNotIn(C,plan.depths)
        self.assertTrue(any(p.status == 'failed' and p.compartment_id == C for p in plan.probes))
        self.assertNotIn('secret raw exception',str(plan_to_dict(plan)))

    def test_pending_absent_search_and_service_list_is_inspected(self):
        n = replace(node('pending',C), lifecycle_state='PENDING_DELETION', metadata={'scheduled_at':'2026-10-10T12:00:00Z'}, blockers=('Waiting for deletion',))
        self.g.add(n)
        old = discover(self.g,P,self.registry)
        class Omitted(Things):
            def discover(self, gateway, compartment_id, region):
                return [], [], [Probe(self.name,region,compartment_id,'complete','')]
        new = discover(self.g,P,Registry({'things':Omitted()}),old)
        self.assertIn('pending',new.nodes)
        self.assertEqual(new.nodes['pending'].lifecycle_state,'PENDING_DELETION')
        self.assertTrue(new.nodes['pending'].blockers)
        del self.g.resources['pending']
        absent = discover(self.g,P,Registry({'things':Omitted()}),new)
        self.assertEqual(absent.nodes['pending'].action,'unresolved')
        self.assertTrue(absent.nodes['pending'].blockers)

    def test_refresh_rejects_different_boundary(self):
        old = discover(self.g,P,self.registry)
        with self.assertRaises(CleanupError):
            discover(self.g,C,self.registry,old)
        self.g.tenancy_id='other'
        with self.assertRaises(CleanupError):
            discover(self.g,P,self.registry,old)

    def test_search_only_known_type_cannot_approve_missing_service_evidence(self):
        self.g.search = [dict(identifier='unlisted',resource_type='Thing',compartment_id=C,display_name='',lifecycle_state='ACTIVE')]
        plan=discover(self.g,P,self.registry)
        self.assertEqual(plan.nodes['unlisted'].action,'unresolved')
        self.assertNotIn('unlisted',plan.depths)

    def test_cascade_owner_with_external_declared_member_blocks(self):
        owner=node('owner',metadata={'cascade_members':['member','external']})
        member=node('member',metadata={'cascade_owner':'owner','cascade_verified':True})
        nodes,_=collapse_cascades({'owner':owner,'member':member},[])
        self.assertEqual(nodes['owner'].action,'unresolved')
        self.assertEqual(nodes['member'].action,'unresolved')

    def test_graph_blocks_unverified_cascade_and_reports_verified_members_separately(self):
        from compartment_cleanup.graph import compute_depths
        depths,blockers=compute_depths({'member':node('member',action='cascade'),'owner':node('owner')},[Edge('member','owner','membership')])
        self.assertNotIn('member',depths)
        self.assertIn('member',blockers)
        self.assertNotIn('owner',depths)

    def test_missing_historical_child_requires_explicit_terminal_iam_read(self):
        saved=discover(self.g,P,self.registry)
        del self.g.compartment_links[C]
        uncertain=discover(self.g,P,self.registry,saved)
        self.assertIn(C,uncertain.compartments)
        self.assertEqual(uncertain.nodes[C].action,'unresolved')
        self.g.responses[('identity','r1','get_compartment')] = ({'id':C,'compartment_id':P,'lifecycle_state':'DELETED'}, {})
        # Parent GET remains live; this fixture limits the terminal response to C.
        original_read=self.g.read
        def read(service,region,operation,params,endpoint=None):
            if operation == 'get_compartment' and params['compartment_id'] == P:
                return {'id':P,'compartment_id':T,'lifecycle_state':'ACTIVE'},{}
            return original_read(service,region,operation,params,endpoint)
        self.g.read=read
        terminal=discover(self.g,P,self.registry,saved)
        self.assertNotIn(C,terminal.nodes)
        self.assertNotIn(C,terminal.compartments)

    def test_blocked_cascade_member_blocks_owner(self):
        owner=node('owner',metadata={'cascade_members':['member']})
        member=replace(node('member',metadata={'cascade_owner':'owner','cascade_verified':True}),blockers=('External consumer',))
        nodes,_=collapse_cascades({'owner':owner,'member':member},[])
        self.assertEqual(nodes['owner'].action,'unresolved')
        self.assertEqual(nodes['member'].action,'unresolved')

    def test_malformed_cascade_metadata_blocks_instead_of_crashing(self):
        from compartment_cleanup.graph import compute_depths
        for metadata in ({'cascade_owner':{}}, {'cascade_owner':'owner','cascade_verified':True}):
            nodes={'member':node('member',metadata=metadata,action='cascade'),'owner':node('owner',metadata={'cascade_members':12})}
            depths,blockers=compute_depths(nodes,[])
            self.assertNotIn('member',depths)
            self.assertIn('member',blockers)

    def test_cascade_owner_outside_members_proven_boundary_blocks(self):
        owner=node('owner','ocid1.compartment.oc1..outside',metadata={'cascade_members':['member']})
        member=node('member',metadata={'cascade_owner':'owner','cascade_verified':True})
        nodes,_=collapse_cascades({'owner':owner,'member':member},[])
        self.assertEqual(nodes['member'].action,'unresolved')
        self.assertEqual(nodes['owner'].action,'unresolved')

    def test_missing_historical_resource_retains_dependency_evidence(self):
        self.g.add(node('x',C,metadata={'target_id':'y'}));self.g.add(node('y',C))
        old=discover(self.g,P,self.registry)
        del self.g.resources['x']
        refreshed=discover(self.g,P,self.registry,old)
        self.assertIn(Edge('x','y','Typed field: target_id'),refreshed.edges)
        self.assertTrue(refreshed.nodes['x'].blockers)
        self.assertNotIn('y',refreshed.depths)
        self.assertEqual(refreshed.nodes['x'].action,'unresolved')

    def test_report_retains_cascade_members_without_listing_them_as_runnable(self):
        from compartment_cleanup.reporting import render_report
        from compartment_cleanup.model import State
        self.g.add(node('owner',metadata={'cascade_members':['member']}))
        self.g.add(node('member',metadata={'cascade_owner':'owner','cascade_verified':True}))
        plan=discover(self.g,P,self.registry)
        report=render_report(plan,State(1,T,P,{}))
        self.assertIn('member | Thing',report)
        self.assertIn('cascade owner: owner',report)
        self.assertNotIn('member',plan.depths)

    def test_refresh_reports_moved_resource_when_only_direct_inspection_finds_it(self):
        self.g.add(node('moved',C))
        saved=discover(self.g,P,self.registry)
        self.g.add(node('moved',P))
        class Omitted(Things):
            def discover(self,gateway,compartment_id,region):
                return [],[],[Probe(self.name,region,compartment_id,'complete','')]
        live=discover(self.g,P,Registry({'things':Omitted()}),saved)
        self.assertEqual(compare_plan(saved,live)['moved'],['moved'])
        self.assertEqual(live.nodes['moved'].action,'unresolved')
        validate_scope(live,P)

    def test_nested_cascade_unsafe_grandchild_blocks_every_ancestor(self):
        from compartment_cleanup.graph import compute_depths
        for reason in ('external', 'unverified'):
            root=node('root',metadata={'cascade_members':['middle']})
            middle=node('middle',metadata={'cascade_owner':'root','cascade_verified':True,'cascade_members':['grandchild']})
            grandchild=node('grandchild',metadata={'cascade_owner':'middle','cascade_verified':False})
            initial={'root':root,'middle':middle}
            if reason == 'unverified':
                initial['grandchild']=grandchild
            for order in (list(initial),list(reversed(initial))):
                nodes,edges=collapse_cascades({key:initial[key] for key in order},[])
                depths,_=compute_depths(nodes,edges)
                self.assertEqual(nodes['root'].action,'unresolved')
                self.assertEqual(nodes['middle'].action,'unresolved')
                self.assertNotIn('root',depths)

    def test_lifecycle_only_refresh_revokes_saved_cascade_membership(self):
        self.g.add(node('owner',metadata={'cascade_members':['member']}))
        self.g.add(node('member',metadata={'cascade_owner':'owner','cascade_verified':True}))
        saved=discover(self.g,P,self.registry)
        self.g.add(node('owner',metadata={'cascade_members':['member','external']}))
        class Omitted(Things):
            def discover(self,gateway,compartment_id,region):
                return [],[],[Probe(self.name,region,compartment_id,'complete','')]
        live=discover(self.g,P,Registry({'things':Omitted()}),saved)
        self.assertEqual(live.nodes['owner'].action,'unresolved')
        self.assertEqual(live.nodes['member'].action,'unresolved')
        self.assertNotIn('owner',live.depths)
        self.assertIsNot(live.nodes['member'].metadata.get('cascade_verified'),True)
        self.assertNotIn('cascade_members',live.nodes['owner'].metadata)

    def test_partial_cascade_inventory_cannot_renew_old_membership_proof(self):
        for missing in ({'owner'},{'member'},{'owner','member'}):
            self.g=Inventory()
            self.g.add(node('owner',metadata={'cascade_members':['member']}))
            self.g.add(node('member',metadata={'cascade_owner':'owner','cascade_verified':True}))
            saved=discover(self.g,P,self.registry)
            class Partial(Things):
                def discover(self,gateway,compartment_id,region):
                    found,edges,probes=super().discover(gateway,compartment_id,region)
                    return [n for n in found if n.key not in missing],edges,probes
            live=discover(self.g,P,Registry({'things':Partial()}),saved)
            self.assertEqual(live.nodes['owner'].action,'unresolved',str(missing))
            self.assertNotIn('owner',live.depths,str(missing))
            if 'owner' in missing:
                self.assertNotIn('cascade_members',live.nodes['owner'].metadata)
            if 'member' in missing:
                self.assertIsNot(live.nodes['member'].metadata.get('cascade_verified'),True)

    def test_invalid_parent_cannot_inject_search_query(self):
        with self.assertRaises(CleanupError):
            discover(self.g,P + "' or true",self.registry)
        self.assertFalse(any(e[3] == 'search_resources' for e in self.g.events))

    def test_verified_cascade_remaps_both_directions_preserving_members(self):
        owner=node('owner',metadata={'cascade_members':['member']})
        member=node('member',metadata={'cascade_owner':'owner','cascade_verified':True})
        nodes,edges=collapse_cascades({n.key:n for n in (owner,member,node('consumer'),node('after'))},
            [Edge('consumer','member','consumer reference'),Edge('member','after','member requirement'),Edge('member','owner','ownership')])
        self.assertEqual(nodes['member'].action,'cascade')
        self.assertEqual(edges,[Edge('consumer','owner','consumer reference'),Edge('owner','after','member requirement')])
        self.g.add(owner); self.g.add(member); self.g.add(node('consumer',metadata={'target_id':'member'}))
        plan=discover(self.g,P,self.registry)
        self.assertNotIn('member',plan.depths)
        self.assertGreater(plan.depths['consumer'],plan.depths['owner'])

    def test_invalid_cascade_unknown_external_cycle_and_membership_block(self):
        for metadata in ({'cascade_owner':'unknown','cascade_verified':True},
                         {'cascade_owner':'owner','cascade_verified':False},
                         {'cascade_owner':'owner','cascade_verified':True}):
            nodes,_=collapse_cascades({'member':node('member',metadata=metadata),'owner':node('owner',metadata={'cascade_members':[]})},[])
            self.assertEqual(nodes['member'].action,'unresolved')
        nodes,_=collapse_cascades({'a':node('a',metadata={'cascade_owner':'b','cascade_verified':True,'cascade_members':['b']}),
                                  'b':node('b',metadata={'cascade_owner':'a','cascade_verified':True,'cascade_members':['a']})},[])
        self.assertTrue(all(n.action=='unresolved' for n in nodes.values()))

    def test_compare_reports_relationship_metadata_and_coverage_drift_without_expanding_saved(self):
        self.g.add(node('x',C,metadata={'target_id':'y'}));self.g.add(node('y',C))
        saved=discover(self.g,P,self.registry)
        self.g.add(replace(self.g.resources['x'],display_name='renamed'))
        live=discover(self.g,P,self.registry)
        self.assertEqual(compare_plan(saved,live),{'added':[],'moved':[],'changed':[]})
        self.g.add(node('new',C));self.g.add(node('x',P,metadata={'target_id':'new'}))
        live=discover(self.g,P,self.registry)
        diff=compare_plan(saved,live)
        self.assertEqual(diff['added'],['new'])
        self.assertEqual(diff['moved'],['x'])
        self.assertIn('x',diff['changed'])
        self.assertNotIn('new',saved.nodes)
        live.probes.append(Probe('extra','r1',C,'failed',''))
        self.assertIn(C,compare_plan(saved,live)['changed'])


if __name__ == '__main__':
    unittest.main()
