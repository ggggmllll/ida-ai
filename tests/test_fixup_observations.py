import unittest
from types import SimpleNamespace

from ida_ai.fixup_observations import collect_fixups
from ida_ai.virtual_tables import trace_thunk_chain


class FakeFixups:
    def __init__(self, addresses=(8, 16, 24), size=8):
        self.addresses = addresses
        self.size = size

    def get_first_fixup_ea(self):
        return self.addresses[0] if self.addresses else 0xFFFFFFFF

    def get_next_fixup_ea(self, ea):
        return next((value for value in self.addresses if value > ea), 0xFFFFFFFF)

    def fixup_data_t(self):
        return SimpleNamespace(get_type=lambda: 7, get_flags=lambda: 2,
            get_base=lambda: 0x1000, is_custom=lambda: self.size < 0,
            off=0x234, displacement=-4, sel=0)

    def get_fixup(self, fd, ea):
        return True

    def calc_fixup_size(self, type_):
        return self.size


class FixupObservationTests(unittest.TestCase):
    def collect(self, api=None, ranges=((8, 32),), **kwargs):
        return collect_fixups(api or FakeFixups(), lambda ea, size: b'\xAA' * size,
                              ranges, 0xFFFFFFFF, **kwargs)

    def test_scope_and_loaded_bytes_are_not_targets(self):
        items, coverage = self.collect(ranges=((16, 24),))
        self.assertEqual([item['source_ea'] for item in items], [16])
        self.assertEqual(items[0]['loaded_bytes_hex'], 'aa' * 8)
        self.assertEqual(items[0]['displacement'], -4)
        self.assertNotIn('target_ea', items[0])
        self.assertFalse(coverage['runtime_targets_decoded'])

    def test_merged_chunks_allow_spanning_fixups(self):
        items, coverage = self.collect(ranges=((8, 12), (12, 32)))
        self.assertEqual(len(items), 3)
        self.assertEqual(coverage['status'], 'complete_within_ranges')

    def test_custom_size_and_range_boundary_are_partial(self):
        items, coverage = self.collect(FakeFixups(size=-1))
        self.assertIsNone(items[0]['size'])
        self.assertEqual(coverage['status'], 'partial')
        items, coverage = self.collect(ranges=((8, 10),))
        self.assertEqual(items[0]['bytes_status'], 'unknown_size_or_outside_range')

    def test_budget_and_broken_enumerator(self):
        items, coverage = self.collect(max_entries=1)
        self.assertEqual(len(items), 1)
        self.assertEqual(coverage['status'], 'truncated')
        api = FakeFixups()
        api.get_next_fixup_ea = lambda ea: 8
        items, coverage = self.collect(api)
        self.assertEqual(len(items), 1)
        self.assertEqual(coverage['status'], 'partial')

    def test_missing_api_or_get_fixup_error(self):
        items, coverage = collect_fixups(None, None, [(8, 32)], 0xFFFFFFFF)
        self.assertEqual(coverage['status'], 'unsupported_api')
        api = FakeFixups()
        api.get_fixup = lambda fd, ea: False
        items, coverage = self.collect(api)
        self.assertEqual(coverage['visited'], 3)
        self.assertTrue(all(item['status'] == 'partial' for item in items))

    def test_unreadable_bytes(self):
        items, coverage = collect_fixups(FakeFixups(), lambda ea, size: None, [(8, 32)], 0xFFFFFFFF)
        self.assertEqual(coverage['status'], 'partial')
        self.assertEqual(items[0]['bytes_status'], 'unreadable')


class ThunkChainTests(unittest.TestCase):
    def functions(self):
        return {8: {'is_thunk': 1, 'thunk_target_ea': 16},
                16: {'is_thunk': 1, 'thunk_target_ea': 24},
                24: {'is_thunk': 0, 'thunk_target_ea': None}}

    def test_multihop_and_unknown_adjustment(self):
        result = trace_thunk_chain(self.functions(), 8)
        self.assertEqual(result['chain'], [8, 16, 24])
        self.assertEqual(result['final_implementation_ea'], 24)
        self.assertEqual(result['this_adjustment'], 'unknown')

    def test_cycle_and_budget_never_claim_final(self):
        functions = self.functions()
        functions[24] = {'is_thunk': 1, 'thunk_target_ea': 8}
        result = trace_thunk_chain(functions, 8)
        self.assertEqual(result['chain'], [8, 16, 24, 8])
        self.assertEqual(result['status'], 'cycle')
        self.assertIsNone(result['final_implementation_ea'])
        self.assertEqual(trace_thunk_chain(functions, 8, max_hops=1)['status'], 'max_hops')

    def test_missing_edge_and_unexported_target(self):
        functions = self.functions()
        functions[16]['thunk_target_ea'] = None
        self.assertEqual(trace_thunk_chain(functions, 8)['status'], 'missing_target')
        functions[16]['thunk_target_ea'] = 32
        self.assertEqual(trace_thunk_chain(functions, 8)['status'], 'external_or_unexported')
