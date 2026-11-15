import json
import unittest
from unittest.mock import patch
import e2e_bitperfect as e2e


class ControllerRows(unittest.TestCase):
    def test_receiver_names_do_not_hide_existing_subscriptions(self):
        rows = [
            {"rx_channel": name, "rx_device": "RECORDER", "tx_device": "SOURCE"}
            for name in ("RX1", "RX 2", "Lead  vocal")
        ] + [{"rx_channel": "01", "rx_device": "SINK", "tx_device": "RECORDER"}]
        with patch.object(e2e, "netaudio", return_value=json.dumps(rows) + "\ncontroller warning on stderr"):
            self.assertEqual(e2e.subscriptions_on("RECORDER"), rows[:3])
            self.assertEqual(e2e.subscriptions_on("SINK"), rows[3:])

    def test_invalid_inventory_cannot_mean_no_existing_routes(self):
        for output in ("controller unavailable", "{}", "[{}]", '[{"rx_device": 17}]'):
            with self.subTest(output=output), patch.object(e2e, "netaudio", return_value=output):
                with self.assertRaises(SystemExit) as result:
                    e2e.subscriptions_on("RECORDER")
                self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
