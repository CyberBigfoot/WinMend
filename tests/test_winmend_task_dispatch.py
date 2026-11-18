"""Tests for task-id -> handler dispatch on WMTaskHost.

The Qt runner resolves a task by name (``getattr(host, WM_HANDLERS[task.id])``)
while the host also binds one WMBoolVar per task under its own id. Two task ids
-- stop_background_apps and disable_startup_apps -- are also the names of the
methods that run them, so an unguarded bind shadows the method and the task dies
with "'WMBoolVar' object is not callable" the moment it runs. These tests pin
both halves: the selection var and the handler must coexist for every task.
"""

import unittest

import WinMend as W


class TaskHandlerDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # WMTaskHost deliberately skips its tkinter parent's __init__ and needs
        # no QApplication, so a real host can be built here.
        cls.host = W.WMTaskHost(None)

    def test_every_task_has_a_callable_handler(self):
        broken = []
        for task in W.WM_TASKS:
            name = W.WM_HANDLERS.get(task.id)
            self.assertIsNotNone(name, f"{task.id} has no WM_HANDLERS entry")
            attr = getattr(self.host, name, None)
            if not callable(attr):
                broken.append((task.id, name, type(attr).__name__))
        self.assertEqual(broken, [], f"handlers shadowed by non-callables: {broken}")

    def test_colliding_ids_keep_their_executor_method(self):
        for task_id in ("stop_background_apps", "disable_startup_apps"):
            with self.subTest(task_id=task_id):
                self.assertTrue(callable(getattr(self.host, task_id)))

    def test_every_task_has_its_own_selection_var(self):
        for task in W.WM_TASKS:
            with self.subTest(task=task.id):
                self.assertIsInstance(self.host.vars[task.id], W.WMBoolVar)
        self.assertEqual(len(self.host.vars), len(W.WM_TASKS))

    def test_legacy_var_aliases_share_the_selection_var(self):
        # run_selected_tasks() and _task_var_map() read the "_var" aliases; the
        # Qt cards write self.vars[id]. They must be the same object.
        self.assertIs(self.host.stop_background_apps_var,
                      self.host.vars["stop_background_apps"])
        self.assertIs(self.host.disable_startup_apps_var,
                      self.host.vars["disable_startup_apps"])

    def test_task_var_map_holds_only_selection_vars(self):
        self.assertEqual(set(self.host._task_var_map()), {task.id for task in W.WM_TASKS})
        for task_id, var in self.host._task_var_map().items():
            with self.subTest(task=task_id):
                self.assertIsInstance(var, W.WMBoolVar)
                self.assertIs(var, self.host.vars[task_id])

    def test_checking_a_card_is_visible_to_the_legacy_selection_path(self):
        var = self.host.vars["stop_background_apps"]
        try:
            var.set(True)
            self.assertTrue(self.host.stop_background_apps_var.get())
            self.assertTrue(
                self.host._task_var_map()["stop_background_apps"].get())
        finally:
            var.set(False)


if __name__ == "__main__":
    unittest.main()
