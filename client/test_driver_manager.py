import os
import tempfile
import unittest
from unittest import mock

import driver_manager as dm
import redirect_driver as rd


class TestDriverManagerLogic(unittest.TestCase):
    def test_find_default_package_prefers_fre_over_chk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            driver_dir = os.path.join(tmpdir, "driver")
            fre_dir = os.path.join(driver_dir, "objfre_win7_amd64", "amd64")
            chk_dir = os.path.join(driver_dir, "objchk_win7_amd64", "amd64")
            os.makedirs(fre_dir)
            os.makedirs(chk_dir)

            inf_file = os.path.join(driver_dir, "netlwf.inf")
            fre_sys = os.path.join(fre_dir, "ndislwf.sys")
            chk_sys = os.path.join(chk_dir, "ndislwf.sys")
            for path in (inf_file, fre_sys, chk_sys):
                with open(path, "wb") as fp:
                    fp.write(b"dummy")

            mgr = dm.NdisLwfDriverManager(project_root=tmpdir)
            found_inf, found_sys = mgr.find_default_package(arch="amd64")
            self.assertEqual(found_inf, inf_file)
            self.assertEqual(found_sys, fre_sys)

    def test_stage_package_collects_inf_sys_and_cat(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_a = os.path.join(tmpdir, "a")
            dir_b = os.path.join(tmpdir, "b")
            os.makedirs(dir_a)
            os.makedirs(dir_b)
            inf_file = os.path.join(dir_a, "netlwf.inf")
            sys_file = os.path.join(dir_b, "ndislwf.sys")
            cat_file = os.path.join(dir_b, "ndislwf.cat")
            for p, content in ((inf_file, b"inf"), (sys_file, b"sys"), (cat_file, b"cat")):
                with open(p, "wb") as fp:
                    fp.write(content)

            staging_dir, staged_inf = dm.NdisLwfDriverManager._stage_package(inf_file, sys_file)
            try:
                self.assertTrue(os.path.isfile(staged_inf))
                self.assertTrue(os.path.isfile(os.path.join(staging_dir, "ndislwf.sys")))
                self.assertTrue(os.path.isfile(os.path.join(staging_dir, "ndislwf.cat")))
            finally:
                import shutil
                shutil.rmtree(staging_dir, ignore_errors=True)

    def test_query_status_states(self):
        mgr = dm.NdisLwfDriverManager()

        with mock.patch.object(mgr, "is_admin", return_value=True), \
             mock.patch.object(mgr, "_query_scm_service_state", return_value=(False, 0)):
            st = mgr.query_status()
            self.assertEqual(st.state, dm.DriverState.NOT_INSTALLED)
            self.assertFalse(st.installed)
            self.assertFalse(st.running)

        with mock.patch.object(mgr, "is_admin", return_value=True), \
             mock.patch.object(mgr, "_query_scm_service_state", return_value=(True, dm.SERVICE_STOPPED)), \
             mock.patch.object(mgr, "_probe_device", return_value=(False, "not ready")):
            st = mgr.query_status()
            self.assertEqual(st.state, dm.DriverState.STOPPED)
            self.assertTrue(st.installed)
            self.assertFalse(st.running)

        with mock.patch.object(mgr, "is_admin", return_value=True), \
             mock.patch.object(mgr, "_query_scm_service_state", return_value=(True, dm.SERVICE_RUNNING)), \
             mock.patch.object(mgr, "_probe_device", return_value=(True, "ok")):
            st = mgr.query_status()
            self.assertEqual(st.state, dm.DriverState.RUNNING)
            self.assertTrue(st.installed)
            self.assertTrue(st.running)
            self.assertTrue(st.device_ready)

    def test_install_and_uninstall_via_netcfg_mock(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            driver_dir = os.path.join(tmpdir, "driver")
            os.makedirs(driver_dir)
            inf_file = os.path.join(driver_dir, "netlwf.inf")
            sys_file = os.path.join(driver_dir, "ndislwf.sys")
            for p in (inf_file, sys_file):
                with open(p, "wb") as fp:
                    fp.write(b"x")

            mgr = dm.NdisLwfDriverManager(project_root=tmpdir)
            stopped_status = dm.DriverStatus(dm.DriverState.STOPPED, True, False)
            running_status = dm.DriverStatus(dm.DriverState.RUNNING, True, True, device_ready=True)
            not_installed_status = dm.DriverStatus(dm.DriverState.NOT_INSTALLED, False, False)

            with mock.patch.object(mgr, "is_admin", return_value=True), \
                 mock.patch.object(dm, "find_netcfg_executable", return_value=r"C:\Windows\System32\netcfg.exe"), \
                 mock.patch.object(mgr, "_run_netcfg", return_value=(False, "ok")) as run_netcfg, \
                 mock.patch.object(mgr, "query_status", return_value=stopped_status), \
                 mock.patch.object(mgr, "start", return_value=running_status) as start_mock:
                st = mgr.install(start_after_install=True)
                self.assertEqual(st.state, dm.DriverState.RUNNING)
                start_mock.assert_called_once()
                args = run_netcfg.call_args[0][1]
                self.assertEqual(args[0:2], ["-v", "-l"])
                self.assertEqual(args[3:], ["-c", "s", "-i", dm.COMPONENT_ID])

            with mock.patch.object(mgr, "is_admin", return_value=True), \
                 mock.patch.object(dm, "find_netcfg_executable", return_value=r"C:\Windows\System32\netcfg.exe"), \
                 mock.patch.object(mgr, "_run_netcfg", return_value=(True, "reboot required")) as run_netcfg, \
                 mock.patch.object(mgr, "stop", return_value=stopped_status) as stop_mock, \
                 mock.patch.object(mgr, "query_status", return_value=not_installed_status):
                st = mgr.uninstall()
                stop_mock.assert_called_once()
                run_netcfg.assert_called_once_with(r"C:\Windows\System32\netcfg.exe", ["-v", "-u", dm.COMPONENT_ID])
                self.assertEqual(st.state, dm.DriverState.NOT_INSTALLED)
                self.assertTrue(st.reboot_required)

    def test_requires_admin_for_mutating_actions(self):
        mgr = dm.NdisLwfDriverManager()
        with mock.patch.object(mgr, "is_admin", return_value=False):
            with self.assertRaises(dm.DriverManagerError):
                mgr.install()
            with self.assertRaises(dm.DriverManagerError):
                mgr.uninstall()
            with self.assertRaises(dm.DriverManagerError):
                mgr.start()


class TestStartupDriverFlow(unittest.TestCase):
    _app = None

    def _make_page(self, fake_mgr, tmpdir):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt5.QtWidgets import QApplication
        import main as app_main

        if TestStartupDriverFlow._app is None:
            TestStartupDriverFlow._app = QApplication.instance() or QApplication([])

        class EmptyDriver:
            device_path = rd.DEVICE_PATH

            def list_rules(self):
                return []

        store = rd.RuleNameStore(os.path.join(tmpdir, "names.json"))
        return app_main, app_main.PortRedirectPage(driver=EmptyDriver(), name_store=store, driver_manager=fake_mgr)

    def test_startup_prompts_install_when_not_installed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_mgr = mock.MagicMock()
            fake_mgr.query_status.return_value = dm.DriverStatus(dm.DriverState.NOT_INSTALLED, False, False)
            fake_mgr.find_default_package.return_value = ("netlwf.inf", "ndislwf.sys")
            fake_mgr.install.return_value = dm.DriverStatus(dm.DriverState.RUNNING, True, True, device_ready=True)

            app_main, page = self._make_page(fake_mgr, tmpdir)
            from PyQt5.QtWidgets import QMessageBox

            with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.Yes) as q_mock, \
                 mock.patch.object(QMessageBox, "information"):
                page.ensure_driver_ready_on_startup()
                q_mock.assert_called_once()
                fake_mgr.install.assert_called_once_with(
                    inf_path="netlwf.inf", sys_path="ndislwf.sys", start_after_install=True
                )

            fake_mgr.install.reset_mock()
            with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.No):
                page.ensure_driver_ready_on_startup()
                fake_mgr.install.assert_not_called()

    def test_startup_auto_starts_when_stopped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_mgr = mock.MagicMock()
            fake_mgr.query_status.side_effect = [
                dm.DriverStatus(dm.DriverState.STOPPED, True, False),   # __init__ refresh_driver_status
                dm.DriverStatus(dm.DriverState.STOPPED, True, False),   # __init__ load_rules
                dm.DriverStatus(dm.DriverState.STOPPED, True, False),   # startup check
                dm.DriverStatus(dm.DriverState.RUNNING, True, True, device_ready=True),  # post-start refresh
                dm.DriverStatus(dm.DriverState.RUNNING, True, True, device_ready=True),  # post-start load_rules
            ]
            fake_mgr.start.return_value = dm.DriverStatus(dm.DriverState.RUNNING, True, True, device_ready=True)

            _app_main, page = self._make_page(fake_mgr, tmpdir)
            page.ensure_driver_ready_on_startup()
            fake_mgr.start.assert_called_once()

    def test_startup_does_nothing_when_already_running(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_mgr = mock.MagicMock()
            fake_mgr.query_status.return_value = dm.DriverStatus(
                dm.DriverState.RUNNING, True, True, device_ready=True
            )
            _app_main, page = self._make_page(fake_mgr, tmpdir)
            from PyQt5.QtWidgets import QMessageBox

            with mock.patch.object(QMessageBox, "question") as q_mock:
                page.ensure_driver_ready_on_startup()
                q_mock.assert_not_called()
                fake_mgr.start.assert_not_called()
                fake_mgr.install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
