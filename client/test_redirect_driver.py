import os
import struct
import tempfile
import unittest

import redirect_driver as rd


class TestRedirectDriverCodec(unittest.TestCase):
    def test_ioctl_codes_match_filteruser_h(self):
        # FILE_DEVICE_PHYSICAL_NETCARD = 0x17, METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0
        self.assertEqual(rd.IOCTL_FILTER_ADD_REDIRECT_RULE, (0x17 << 16) | (14 << 2))
        self.assertEqual(rd.IOCTL_FILTER_DEL_REDIRECT_RULE, (0x17 << 16) | (15 << 2))
        self.assertEqual(rd.IOCTL_FILTER_CLEAR_REDIRECT_RULES, (0x17 << 16) | (16 << 2))
        self.assertEqual(rd.IOCTL_FILTER_LIST_REDIRECT_RULES, (0x17 << 16) | (17 << 2))

    def test_struct_sizes_match_c_abi(self):
        self.assertEqual(rd.REDIRECT_RULE_STRUCT.size, 52)
        self.assertEqual(rd.REDIRECT_DEL_RULE_STRUCT.size, 4)

    def test_ipv4_pack_unpack_and_byte_offsets(self):
        rule = rd.RedirectRule(
            rule_id=7,
            orig_ip="10.0.0.10",
            orig_port=80,
            new_ip="192.168.1.20",
            new_port=8080,
            protocol=rd.REDIRECT_PROTO_TCP,
            new_dst_mac="aa:bb:cc:dd:ee:ff",
            local_loopback=True,
        )
        raw = rd.pack_redirect_rule(rule)
        self.assertEqual(len(raw), 52)

        # Verify exact C struct offsets
        self.assertEqual(struct.unpack_from("<L", raw, 0)[0], 7)          # RuleId
        self.assertEqual(raw[4], rd.REDIRECT_AF_IPV4)                    # AddressFamily
        self.assertEqual(raw[5], rd.REDIRECT_PROTO_TCP)                  # Protocol
        self.assertEqual(struct.unpack_from("<H", raw, 6)[0], 0x0003)    # Flags (MAC | LOCAL)
        self.assertEqual(raw[8:12], bytes([10, 0, 0, 10]))               # OrigIp.V4
        self.assertEqual(raw[12:24], b"\x00" * 12)                       # OrigIp padding
        self.assertEqual(raw[24:26], bytes([0x00, 0x50]))                # OrigPort = 80 (BE)
        self.assertEqual(raw[26:28], bytes([0x1F, 0x90]))                # NewPort = 8080 (BE)
        self.assertEqual(raw[28:32], bytes([192, 168, 1, 20]))           # NewIp.V4
        self.assertEqual(raw[32:44], b"\x00" * 12)                       # NewIp padding
        self.assertEqual(raw[44:50], bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        self.assertEqual(raw[50:52], b"\x00\x00")                        # Reserved

        decoded = rd.unpack_redirect_rule(raw)
        self.assertEqual(decoded.rule_id, 7)
        self.assertEqual(decoded.address_family, rd.REDIRECT_AF_IPV4)
        self.assertEqual(decoded.protocol, rd.REDIRECT_PROTO_TCP)
        self.assertEqual(decoded.orig_ip, "10.0.0.10")
        self.assertEqual(decoded.orig_port, 80)
        self.assertEqual(decoded.new_ip, "192.168.1.20")
        self.assertEqual(decoded.new_port, 8080)
        self.assertEqual(decoded.new_dst_mac, "AA:BB:CC:DD:EE:FF")
        self.assertTrue(decoded.local_loopback)

    def test_ipv6_wildcard_ports_and_hyphen_mac(self):
        rule = rd.RedirectRule(
            orig_ip="2001:db8::1",
            orig_port=0,
            new_ip="2001:db8::2",
            new_port=0,
            protocol=rd.REDIRECT_PROTO_ANY,
            new_dst_mac="00-11-22-33-44-55",
            local_loopback=False,
        )
        raw = rd.pack_redirect_rule(rule)
        decoded = rd.unpack_redirect_rule(raw)
        self.assertEqual(decoded.address_family, rd.REDIRECT_AF_IPV6)
        self.assertEqual(decoded.protocol, rd.REDIRECT_PROTO_ANY)
        self.assertEqual(decoded.orig_ip, "2001:db8::1")
        self.assertEqual(decoded.orig_port, 0)
        self.assertEqual(decoded.new_ip, "2001:db8::2")
        self.assertEqual(decoded.new_port, 0)
        self.assertEqual(decoded.new_dst_mac, "00:11:22:33:44:55")
        self.assertFalse(decoded.local_loopback)

    def test_validation_errors(self):
        with self.assertRaises(ValueError):
            rd.pack_redirect_rule(rd.RedirectRule(orig_ip="10.0.0.1", new_ip="2001:db8::1"))
        with self.assertRaises(ValueError):
            rd.pack_redirect_rule(rd.RedirectRule(orig_ip="10.0.0.1", new_ip="10.0.0.2", orig_port=70000))
        with self.assertRaises(ValueError):
            rd.pack_redirect_rule(rd.RedirectRule(orig_ip="10.0.0.1", new_ip="10.0.0.2", new_dst_mac="invalid"))


class TestRuleNameStore(unittest.TestCase):
    def test_crud_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "names.json")
            store = rd.RuleNameStore(path)
            store.set(1, "HTTP 转发")
            store.set(2, "本地环回测试")

            reloaded = rd.RuleNameStore(path)
            self.assertEqual(reloaded.get(1), "HTTP 转发")
            self.assertEqual(reloaded.get(2), "本地环回测试")

            reloaded.prune([2])
            self.assertEqual(reloaded.get(1), "")
            self.assertEqual(reloaded.get(2), "本地环回测试")

            reloaded.delete(2)
            self.assertEqual(reloaded.get(2), "")

            reloaded.set(3, "临时规则")
            reloaded.clear()
            self.assertEqual(rd.RuleNameStore(path).get(3), "")


class TestRedirectDriverClientMock(unittest.TestCase):
    def test_client_ioctl_dispatch(self):
        calls = []
        r1 = rd.RedirectRule(rule_id=1, orig_ip="10.0.0.1", orig_port=80, new_ip="10.0.0.2", new_port=8080)
        r2 = rd.RedirectRule(rule_id=2, orig_ip="2001:db8::1", orig_port=0, new_ip="2001:db8::2", new_port=0, protocol=rd.REDIRECT_PROTO_UDP)

        class FakeClient(rd.RedirectDriverClient):
            def _device_io_control(self, control_code, in_buffer=b"", out_size=0):
                calls.append((control_code, in_buffer, out_size))
                if control_code == rd.IOCTL_FILTER_ADD_REDIRECT_RULE:
                    rule = rd.unpack_redirect_rule(in_buffer)
                    if rule.rule_id == 0:
                        rule.rule_id = 1
                    return rd.pack_redirect_rule(rule)
                if control_code == rd.IOCTL_FILTER_LIST_REDIRECT_RULES:
                    return rd.pack_redirect_rule(r1) + rd.pack_redirect_rule(r2)
                return b""

        client = FakeClient()
        created = client.add_rule(rd.RedirectRule(name="web", orig_ip="10.0.0.1", orig_port=80, new_ip="10.0.0.2", new_port=8080))
        self.assertEqual(created.rule_id, 1)
        self.assertEqual(created.name, "web")

        listed = client.list_rules()
        self.assertEqual(len(listed), 2)
        self.assertEqual(listed[1].address_family, rd.REDIRECT_AF_IPV6)

        client.delete_rule(1)
        self.assertEqual(calls[-1][0], rd.IOCTL_FILTER_DEL_REDIRECT_RULE)
        self.assertEqual(calls[-1][1], struct.pack("<L", 1))

        client.clear_rules()
        self.assertEqual(calls[-1][0], rd.IOCTL_FILTER_CLEAR_REDIRECT_RULES)


class TestGuiIntegration(unittest.TestCase):
    def test_tabs_and_port_redirect_page(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from unittest import mock
        from PyQt5.QtWidgets import QApplication
        import main as app_main
        from net_monitor_page import NetworkMonitorPage

        app = QApplication.instance() or QApplication([])
        self.assertIsNotNone(app)

        class InMemoryDriver:
            device_path = rd.DEVICE_PATH

            def __init__(self):
                self._rules = {}
                self._next = 1

            def list_rules(self):
                return list(self._rules.values())

            def add_rule(self, rule):
                rid = rule.rule_id or self._next
                if rid >= self._next:
                    self._next = rid + 1
                saved = rd.unpack_redirect_rule(rd.pack_redirect_rule(rd.RedirectRule(
                    rule_id=rid,
                    orig_ip=rule.orig_ip,
                    orig_port=rule.orig_port,
                    new_ip=rule.new_ip,
                    new_port=rule.new_port,
                    protocol=rule.protocol,
                    new_dst_mac=rule.new_dst_mac,
                    local_loopback=rule.local_loopback,
                )))
                self._rules[rid] = saved
                return saved

            def update_rule(self, rule):
                return self.add_rule(rule)

            def delete_rule(self, rule_id):
                self._rules.pop(rule_id, None)

            def clear_rules(self):
                self._rules.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            driver = InMemoryDriver()
            store = rd.RuleNameStore(os.path.join(tmpdir, "names.json"))
            created = driver.add_rule(
                rd.RedirectRule(orig_ip="10.0.0.10", orig_port=80, new_ip="10.0.0.20", new_port=8080)
            )
            store.set(created.rule_id, "测试规则A")

            page = app_main.PortRedirectPage(driver=driver, name_store=store)
            self.assertEqual(page.rule_table.rowCount(), 1)
            self.assertEqual(page.rule_table.item(0, 0).text(), "1")
            self.assertEqual(page.rule_table.item(0, 1).text(), "测试规则A")

            with mock.patch("PyQt5.QtWidgets.QMessageBox.warning") as warn_mock:
                win = app_main.MainWindow(auto_check_driver=False)
            self.assertIsNotNone(warn_mock)
            tab_titles = [win.tab_widget.tabText(i) for i in range(win.tab_widget.count())]
            net_idx = tab_titles.index("网络管控")
            port_idx = next(i for i, t in enumerate(tab_titles) if t.startswith("端口重定向"))
            self.assertIsInstance(win.tab_widget.widget(net_idx), NetworkMonitorPage)
            self.assertIsInstance(win.tab_widget.widget(port_idx), app_main.PortRedirectPage)
            self.assertEqual(win.tab_widget.currentIndex(), port_idx)

            # Verify PortRuleDialog validation & rule building (including port 0, MAC, local)
            dlg = app_main.PortRuleDialog()
            dlg.name_edit.setText("本地回环规则")
            dlg.orig_ip_edit.setText("172.16.7.115")
            dlg.orig_port_edit.setText("0")
            dlg.new_ip_edit.setText("192.168.71.128")
            dlg.new_port_edit.setText("4321")
            dlg.tcp_checkbox.setChecked(True)
            dlg.udp_checkbox.setChecked(True)
            dlg.mac_edit.setText("aa-bb-cc-dd-ee-ff")
            dlg.local_checkbox.setChecked(True)
            built = dlg.get_rule()
            self.assertEqual(built.name, "本地回环规则")
            self.assertEqual(built.protocol, rd.REDIRECT_PROTO_ANY)
            self.assertEqual(built.orig_port, 0)
            self.assertEqual(built.new_port, 4321)
            self.assertEqual(built.new_dst_mac, "AA:BB:CC:DD:EE:FF")
            self.assertTrue(built.local_loopback)


if __name__ == "__main__":
    unittest.main()
