import unittest

import z3

from rsve.logic import Sort, Variable
from rsve.model import State
from rsve.memory import (
    ArrayValue,
    MapRef,
    Memory,
    MemoryFault,
    MemoryFaultKind,
    Pointer,
    StructValue,
    index_constraint,
)
from rsve.solver import Map


class Suite(unittest.TestCase):
    def test_pointer_and_nested_field_aliases_update_shared_heap_object(self):
        tx = Memory().transaction()
        inner = tx.new_struct(StructValue.create("Inner", {"count": 1}))
        root = tx.new_struct(StructValue.create("Root", {"child": inner}))
        alias = Pointer(root.object_id)

        child_pointer = tx.load(tx.field_pointer(alias, "child"))
        count_pointer = tx.field_pointer(child_pointer, "count")
        tx.store(count_pointer, 7)

        self.assertEqual(tx.load(tx.load(tx.field_pointer(alias, "child"))).get("count"), 7)

    def test_struct_and_array_values_copy_but_references_remain_aliased(self):
        tx = Memory().transaction()
        shared = tx.new_pointer(5)
        original = StructValue.create("Record", {"value": 1, "shared": shared})
        first = tx.new_struct(original)
        second = tx.new_struct(original)
        tx.store(tx.field_pointer(first, "value"), 2)
        tx.store(shared, 9)

        self.assertEqual(tx.load(tx.field_pointer(first, "value")), 2)
        self.assertEqual(tx.load(tx.field_pointer(second, "value")), 1)
        self.assertEqual(tx.load(tx.load(tx.field_pointer(second, "shared"))), 9)

        array = ArrayValue.create("[2]int", [1, 2])
        changed = array.set(0, 8)
        self.assertEqual(array.get(0), 1)
        self.assertEqual(changed.get(0), 8)

    def test_slices_alias_backing_and_reallocation_requires_capacity(self):
        tx = Memory().transaction()
        base = tx.new_slice([1, 2], capacity=4)
        view = tx.slice_view(base, 1, 2)
        tx.slice_set(view, 0, 6)
        self.assertEqual(tx.slice_get(base, 1), 6)

        grown = tx.append_slice(base, 3)
        self.assertEqual(grown.object_id, base.object_id)
        self.assertEqual(tx.slice_get(grown, 2), 3)
        full = tx.append_slice(grown, 4)
        self.assertEqual(full.object_id, base.object_id)
        with self.assertRaises(MemoryFault) as error:
            tx.append_slice(full, 5)
        self.assertEqual(error.exception.kind, MemoryFaultKind.CAPACITY)

        reallocated = tx.append_slice(full, 5, new_capacity=8)
        self.assertNotEqual(reallocated.object_id, full.object_id)
        self.assertEqual(tx.slice_get(full, 0), 1)
        self.assertEqual(tx.slice_get(reallocated, 4), 5)

    def test_slice_and_array_bounds_are_explicit_panics(self):
        tx = Memory().transaction()
        array = ArrayValue.create("[1]int", [3])
        with self.assertRaises(MemoryFault) as array_error:
            array.get(1)
        self.assertEqual(array_error.exception.kind, MemoryFaultKind.INDEX)
        ref = tx.new_slice([1])
        with self.assertRaises(MemoryFault) as slice_error:
            tx.slice_get(ref, -1)
        self.assertEqual(slice_error.exception.kind, MemoryFaultKind.INDEX)
        with self.assertRaises(MemoryFault) as bounds_error:
            tx.slice_view(ref, 0, 2)
        self.assertEqual(bounds_error.exception.kind, MemoryFaultKind.SLICE_BOUNDS)

    def test_maps_alias_and_nil_map_read_write_semantics(self):
        tx = Memory().transaction()
        first = tx.new_map({"k": 1})
        alias = MapRef(first.object_id)
        tx.map_set(alias, "k", 4)
        self.assertEqual(tx.map_get(first, "k"), 4)
        self.assertEqual(tx.map_get(None, "missing", zero=0), 0)
        tx.map_delete(None, "missing")
        with self.assertRaises(MemoryFault) as error:
            tx.map_set(None, "x", 1)
        self.assertEqual(error.exception.kind, MemoryFaultKind.NIL_MAP_WRITE)

    def test_transaction_overlay_commit_rollback_and_conflict(self):
        tx = Memory().transaction()
        pointer = tx.new_pointer(1)
        initial = tx.commit()

        left = initial.transaction()
        right = initial.transaction()
        left.store(pointer, 2)
        changed = left.commit()
        self.assertEqual(right.load(pointer), 1)
        right.store(pointer, 3)
        with self.assertRaises(MemoryFault) as conflict:
            right.commit(changed)
        self.assertEqual(conflict.exception.kind, MemoryFaultKind.TRANSACTION_CONFLICT)

        rollback = changed.transaction()
        rollback.store(pointer, 8)
        rolled_back = rollback.rollback()
        self.assertEqual(rolled_back.transaction().load(pointer), 2)
        self.assertEqual(changed.transaction().load(pointer), 2)

    def test_index_constraint_is_symbolic_and_concrete_solver_visible(self):
        index = Variable("index", Sort.INT)
        constraint = index_constraint(index, 4)
        translator = Map()
        predicate = translator.expr(constraint)
        symbolic_index = translator.variable(index)
        solver = z3.Solver()
        solver.add(predicate, symbolic_index == 3)
        self.assertEqual(solver.check(), z3.sat)
        solver = z3.Solver()
        solver.add(predicate, symbolic_index == -1)
        self.assertEqual(solver.check(), z3.unsat)

if __name__ == "__main__":
    unittest.main()
