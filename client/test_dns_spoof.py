import os
import struct
import unittest
from unittest import mock

import dns_spoof_driver as ds


class TestDnsSpoofCodec(unittest.TestCase):
    def test_ioctl_codes_match_filteruser_h(self):
        self.assertEqual(ds.IOCTL_FILTER_ADD_DNS_SPOOF_RULE, (0x17 << 16) | (18 << 2))
        self.assertEqual(ds.IOCTL_FILTER_DEL_DNS_SPOOF_RULE, (0x17 << 16) | (19 << 2))
        self.assertEqual(ds.IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES, (0x17 << 16) | (20 << 2))
        self.assertEqual(ds.IOCTL_FILTER_LIST_DNS_SPOOF_RULES, (0x17 << 16) | (21 << 2))

    def test_struct_sizes_match_c_abi(self):
        self.assertEqual(ds.DNS_SPOOF_RULE_STRUCT.size, 288)
        self.assertEqual(ds.DNS_SPOOF_DEL_RULE_STRUCT.size, 4)

    def test_dual_stack_and_wildcard_pack_unpack_offsets(self):
        rule = ds.DnsSpoofRule(
            rule_id=5,
            domain="  *.Baidu.COM.  ",
            fake_ipv4="1.1.1.1",
            fake_ipv6="2001:db8::9",
            ttl=60,
        )
        raw = ds.pack_dns_spoof_rule(rule)
        self.assertEqual(len(raw), 288)

        self.assertEqual(struct.unpack_from("<L", raw, 0)[0], 5)
        self.assertEqual(
            struct.unpack_from("<H", raw, 4)[0],
            ds.DNS_SPOOF_FLAG_HAS_IPV4 | ds.DNS_SPOOF_FLAG_HAS_IPV6 | ds.DNS_SPOOF_FLAG_WILDCARD,
        )
        self.assertEqual(struct.unpack_from("<L", raw, 8)[0], 60)
        self.assertEqual(raw[12:16], bytes([1, 1, 1, 1]))
        self.assertEqual(raw[16:32], bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x09]))
        self.assertTrue(raw[32:].startswith(b"*.baidu.com\x00"))

        decoded = ds.unpack_dns_spoof_rule(raw)
        self.assertEqual(decoded.rule_id, 5)
        self.assertEqual(decoded.domain, "*.baidu.com")
        self.assertTrue(decoded.wildcard)
        self.assertEqual(decoded.fake_ipv4, "1.1.1.1")
        self.assertEqual(decoded.fake_ipv6, "2001:db8::9")
        self.assertEqual(decoded.ttl, 60)

    def test_ipv4_only_and_wildcard_flag_normalization(self):
        rule = ds.DnsSpoofRule(domain="example.org", fake_ipv4="10.20.30.40", wildcard=True)
        decoded = ds.unpack_dns_spoof_rule(ds.pack_dns_spoof_rule(rule))
        self.assertEqual(decoded.domain, "*.example.org")
        self.assertTrue(decoded.wildcard)
        self.assertEqual(decoded.fake_ipv4, "10.20.30.40")
        self.assertEqual(decoded.fake_ipv6, "")

    def test_validation_errors(self):
        # Missing both IPv4 and IPv6
        with self.assertRaises(ValueError):
            ds.pack_dns_spoof_rule(ds.DnsSpoofRule(domain="baidu.com"))
        # Wildcard in middle of domain
        with self.assertRaises(ValueError):
            ds.pack_dns_spoof_rule(ds.DnsSpoofRule(domain="www.*.baidu.com", fake_ipv4="1.1.1.1"))
        # Invalid IPv4
        with self.assertRaises(ValueError):
            ds.pack_dns_spoof_rule(ds.DnsSpoofRule(domain="baidu.com", fake_ipv4="999.1.1.1"))
        # Invalid IPv6
        with self.assertRaises(ValueError):
            ds.pack_dns_spoof_rule(ds.DnsSpoofRule(domain="baidu.com", fake_ipv6="not-an-ip"))


class TestDnsSpoofClientMock(unittest.TestCase):
    def test_ioctl_dispatch_and_cache_flush(self):
        calls = []

        class FakeDnsClient(ds.DnsSpoofDriverClient):
            def _device_io_control(self, control_code, in_buffer=b"", out_size=0):
                calls.append((control_code, in_buffer, out_size))
                if control_code == ds.IOCTL_FILTER_ADD_DNS_SPOOF_RULE:
                    r = ds.unpack_dns_spoof_rule(in_buffer)
                    if r.rule_id == 0:
                        r.rule_id = 1
                    return ds.pack_dns_spoof_rule(r)
                if control_code == ds.IOCTL_FILTER_LIST_DNS_SPOOF_RULES:
                    r1 = ds.DnsSpoofRule(rule_id=1, domain="baidu.com", fake_ipv4="1.1.1.1", ttl=30)
                    return ds.pack_dns_spoof_rule(r1)
                return b""

        client = FakeDnsClient()
        with mock.patch.object(ds, "flush_dns_cache", return_value=True) as flush_mock:
            created = client.add_rule(ds.DnsSpoofRule(domain="baidu.com", fake_ipv4="1.1.1.1"))
            self.assertEqual(created.rule_id, 1)
            self.assertEqual(created.domain, "baidu.com")
            self.assertEqual(flush_mock.call_count, 1)

            listed = client.list_rules()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].fake_ipv4, "1.1.1.1")

            client.delete_rule(1)
            self.assertEqual(calls[-1][0], ds.IOCTL_FILTER_DEL_DNS_SPOOF_RULE)
            self.assertEqual(calls[-1][1], struct.pack("<L", 1))
            self.assertEqual(flush_mock.call_count, 2)

            client.clear_rules()
            self.assertEqual(calls[-1][0], ds.IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES)
            self.assertEqual(flush_mock.call_count, 3)


class TestDnsSpoofGui(unittest.TestCase):
    _app = None

    def test_dns_dialog_page_and_main_window_tab(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt5.QtWidgets import QApplication
        import dns_spoof_page as dp
        import main as app_main

        if TestDnsSpoofGui._app is None:
            TestDnsSpoofGui._app = QApplication.instance() or QApplication([])

        dlg = dp.DnsSpoofRuleDialog()
        dlg.domain_edit.setText("baidu.com")
        dlg.wildcard_checkbox.setChecked(True)
        dlg.ipv4_edit.setText("1.1.1.1")
        dlg.ipv6_edit.setText("2001:db8::1")
        dlg.ttl_edit.setText("45")
        built = dlg.get_rule()
        self.assertEqual(built.domain, "*.baidu.com")
        self.assertTrue(built.wildcard)
        self.assertEqual(built.fake_ipv4, "1.1.1.1")
        self.assertEqual(built.fake_ipv6, "2001:db8::1")
        self.assertEqual(built.ttl, 45)

        # Unchecking wildcard on an existing *.domain rule should strip "*." cleanly
        edit_dlg = dp.DnsSpoofRuleDialog(rule=built)
        self.assertTrue(edit_dlg.wildcard_checkbox.isChecked())
        edit_dlg.wildcard_checkbox.setChecked(False)
        edited = edit_dlg.get_rule()
        self.assertEqual(edited.domain, "baidu.com")
        self.assertFalse(edited.wildcard)

        class InMemoryDnsDriver:
            device_path = ds.DEVICE_PATH

            def __init__(self):
                self._rules = [
                    ds.DnsSpoofRule(rule_id=1, domain="*.baidu.com", fake_ipv4="1.1.1.1", ttl=30, wildcard=True)
                ]
                self._next_id = 2

            def list_rules(self):
                return list(self._rules)

            def add_rule(self, rule, flush_cache=True):
                new_rule = ds.DnsSpoofRule(
                    rule_id=self._next_id,
                    domain=rule.domain,
                    fake_ipv4=rule.fake_ipv4,
                    fake_ipv6=rule.fake_ipv6,
                    ttl=rule.ttl,
                    wildcard=rule.wildcard,
                )
                self._next_id += 1
                self._rules.append(new_rule)
                return new_rule

            def update_rule(self, rule, flush_cache=True):
                for idx, existing in enumerate(self._rules):
                    if existing.rule_id == rule.rule_id:
                        self._rules[idx] = rule
                        return rule
                self._rules.append(rule)
                return rule

            def delete_rule(self, rule_id, flush_cache=True):
                self._rules = [r for r in self._rules if r.rule_id != rule_id]

            def clear_rules(self, flush_cache=True):
                self._rules.clear()

        mem_driver = InMemoryDnsDriver()
        page = dp.DnsSpoofPage(driver=mem_driver)
        self.assertEqual(page.rule_table.rowCount(), 1)
        self.assertEqual(page.rule_table.item(0, 1).text(), "*.baidu.com")
        self.assertEqual(page.rule_table.item(0, 3).text(), "1.1.1.1")

        # Verify remove_selected_rule & clear_rules propagate to driver
        page.rule_table.selectRow(0)
        page.remove_selected_rule()
        self.assertEqual(page.rule_table.rowCount(), 0)
        self.assertEqual(len(mem_driver._rules), 0)

        mem_driver.add_rule(ds.DnsSpoofRule(domain="example.com", fake_ipv4="2.2.2.2", ttl=60))
        page.load_rules(silent=True)
        self.assertEqual(page.rule_table.rowCount(), 1)
        with mock.patch("PyQt5.QtWidgets.QMessageBox.question", return_value=dp.QMessageBox.Yes):
            page.clear_rules()
        self.assertEqual(page.rule_table.rowCount(), 0)

        with mock.patch("PyQt5.QtWidgets.QMessageBox.warning"):
            win = app_main.MainWindow(auto_check_driver=False)
        titles = [win.tab_widget.tabText(i) for i in range(win.tab_widget.count())]
        dns_idx = next(i for i, t in enumerate(titles) if t.startswith("域名欺骗"))
        self.assertIsInstance(win.tab_widget.widget(dns_idx), dp.DnsSpoofPage)
        self.assertIs(win.dns_spoof_page.driver_manager, win.port_redirect_page.driver_manager)

        with mock.patch.object(win.dns_spoof_page, "load_rules") as reload_mock:
            win.port_redirect_page.driverStateChanged.emit()
            self.assertEqual(reload_mock.call_count, 1)
            win.tab_widget.setCurrentIndex(dns_idx)
            self.assertEqual(reload_mock.call_count, 2)


if __name__ == "__main__":
    unittest.main()
