import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = (ROOT / "Windows/Wfp/driver/FuriousWfpCallout.c").read_text(encoding="utf-8")
ENGINE = (ROOT / "Windows/Wfp/service/WfpEngine.cpp").read_text(encoding="utf-8")


class WfpFlowLifecycleContractTests(unittest.TestCase):
    def test_datagram_v4_v6_callouts_are_registered(self):
        self.assertIn("FURIOUS_WFP_DATAGRAM_DATA_V4_CALLOUT", DRIVER)
        self.assertIn("FURIOUS_WFP_DATAGRAM_DATA_V6_CALLOUT", DRIVER)
        self.assertIn("FuriousDatagramDataClassify", DRIVER)
        self.assertIn("FuriousWfpDatagramQueuePushCaptured", DRIVER)
        self.assertIn("NET_BUFFER_LIST_FIRST_NB", DRIVER)
        self.assertIn("NdisGetDataBuffer", DRIVER)
        self.assertIn("FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION", DRIVER)
        self.assertIn("FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION", DRIVER)
        self.assertIn("FuriousSetCalloutRegistered(5, TRUE, calloutId)", DRIVER)

    def test_flow_context_is_associated_with_datagram_data_layer(self):
        self.assertIn(
            "context->LayerId = (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4)",
            DRIVER,
        )
        self.assertIn(
            "FwpsFlowAssociateContext0(\n"
            "        inMetaValues->flowHandle, context->LayerId",
            DRIVER,
        )
        self.assertIn("FuriousGetCalloutId(calloutIndex == 2 ? 4 : 5)", DRIVER)

    def test_capture_is_observation_only_and_checks_policy_generation(self):
        callback = DRIVER.split(
            "static VOID NTAPI FuriousDatagramDataClassify(", 1
        )[1].split("static VOID NTAPI FuriousFlowDelete(", 1)[0]
        self.assertIn("FWP_ACTION_CONTINUE", callback)
        self.assertNotIn("FWP_ACTION_BLOCK", callback)
        self.assertIn("endpoint.PolicyGeneration != context->PolicyGeneration", callback)
        self.assertIn("FWPS_METADATA_FIELD_IP_HEADER_SIZE", callback)
        self.assertIn("FuriousWfpDatagramQueuePushCaptured", callback)

    def test_management_installs_and_removes_udp_datagram_filters(self):
        self.assertIn("FWPM_LAYER_DATAGRAM_DATA_V4", ENGINE)
        self.assertIn("FWPM_LAYER_DATAGRAM_DATA_V6", ENGINE)
        self.assertIn("AddDatagramCaptureFilter", ENGINE)
        self.assertIn("kDatagramDataV4CalloutKey", ENGINE)
        self.assertIn("kDatagramDataV6CalloutKey", ENGINE)
        self.assertIn("FWP_ACTION_CALLOUT_INSPECTION", ENGINE)


class PendingRedirectTableModel:
    """Small behavioral oracle for the driver's consume-once record contract."""

    TTL = 30.0
    LIMIT = 1024

    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self._records = {}

    def insert(self, handle, pid, protocol, family, generation, target, redirected, now):
        with self._lock:
            self._expire(now)
            self._records = {
                key: value for key, value in self._records.items()
                if value["generation"] == generation
            }
            if handle in self._records or len(self._records) >= self.LIMIT:
                return False
            self._records[handle] = {
                "pid": pid, "protocol": protocol, "family": family,
                "generation": generation, "target": target,
                "redirected": redirected, "created": now,
            }
            return True

    def _expire(self, now):
        self._records = {
            key: value for key, value in self._records.items()
            if 0 <= now - value["created"] <= self.TTL
        }

    def take(self, handle, pid, protocol, family, generation, redirected, now):
        with self._lock:
            self._expire(now)
            record = self._records.pop(handle, None)
            if record is None:
                return None
            expected = (pid, protocol, family, generation, redirected)
            actual = (record["pid"], record["protocol"], record["family"],
                      record["generation"], record["redirected"])
            return record if actual == expected else None

    def process_exit(self, pid):
        with self._lock:
            self._records = {
                key: value for key, value in self._records.items()
                if value["pid"] != pid
            }


class WfpPendingRedirectRecordTests(unittest.TestCase):
    def test_driver_joins_by_transport_endpoint_and_checks_real_redirected_tuple(self):
        redirect = DRIVER.split("static VOID NTAPI FuriousClassify(", 1)[1].split(
            "static NTSTATUS NTAPI FuriousNotify(", 1
        )[0]
        flow = DRIVER.split("static VOID NTAPI FuriousFlowEstablishedClassify(", 1)[1].split(
            "static VOID NTAPI FuriousDatagramDataClassify(", 1
        )[0]
        self.assertIn("FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE", redirect)
        self.assertIn("transportEndpointHandle", redirect)
        self.assertIn("FuriousInsertPendingRedirectRecord", redirect)
        self.assertIn("FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE", flow)
        self.assertIn("FuriousTakePendingRedirectRecord", flow)
        for field in ("ProcessId", "Protocol", "AddressFamily", "PolicyGeneration",
                      "RedirectPortHostOrder", "RedirectAddress"):
            self.assertIn(field, DRIVER)

    def test_flow_context_and_datagram_keep_the_original_destination(self):
        flow = DRIVER.split("static VOID NTAPI FuriousFlowEstablishedClassify(", 1)[1].split(
            "static VOID NTAPI FuriousDatagramDataClassify(", 1
        )[0]
        datagram = DRIVER.split("static VOID NTAPI FuriousDatagramDataClassify(", 1)[1].split(
            "static VOID NTAPI FuriousFlowDelete(", 1
        )[0]
        self.assertIn("context->OriginalAddress", flow)
        self.assertIn("context->OriginalPortHostOrder", flow)
        self.assertIn("remotePort = context->OriginalPortHostOrder", datagram)
        self.assertIn("remoteAddress, context->OriginalAddress", datagram)

    def test_driver_bounds_records_and_cleans_expired_process_and_policy_entries(self):
        self.assertIn("FURIOUS_WFP_PENDING_REDIRECT_TTL_100NS", DRIVER)
        self.assertIn("FURIOUS_WFP_PENDING_REDIRECT_MAX_RECORDS 1024", DRIVER)
        self.assertIn("STATUS_OBJECT_NAME_COLLISION", DRIVER)
        self.assertIn("FuriousRemovePendingRedirectRecordsForProcess", DRIVER)
        self.assertIn("FuriousClearPendingRedirectRecords", DRIVER)
        self.assertIn("old->PolicyGeneration != generation", DRIVER)

    def test_concurrent_distinct_flows_match_their_own_original_destinations(self):
        from concurrent.futures import ThreadPoolExecutor
        table = PendingRedirectTableModel()
        items = [
            (1000 + i, 200 + i, 17, 4, 9, (f"198.51.100.{i + 1}", 53),
             ("127.0.0.1", 40000 + i))
            for i in range(24)
        ]
        with ThreadPoolExecutor(max_workers=12) as pool:
            inserted = list(pool.map(
                lambda x: table.insert(*x, now=10.0), items
            ))
        self.assertTrue(all(inserted))
        with ThreadPoolExecutor(max_workers=12) as pool:
            matched = list(pool.map(
                lambda x: table.take(x[0], x[1], x[2], x[3], x[4], x[6], now=11.0),
                items,
            ))
        self.assertEqual([x["target"] for x in matched], [x[5] for x in items])

    def test_multiple_flows_from_one_process_do_not_cross_associate(self):
        table = PendingRedirectTableModel()
        self.assertTrue(table.insert(11, 77, 17, 4, 3, ("203.0.113.1", 53),
                                     ("127.0.0.1", 45001), 0))
        self.assertTrue(table.insert(12, 77, 17, 4, 3, ("203.0.113.2", 443),
                                     ("127.0.0.1", 45002), 0))
        second = table.take(12, 77, 17, 4, 3, ("127.0.0.1", 45002), 1)
        first = table.take(11, 77, 17, 4, 3, ("127.0.0.1", 45001), 1)
        self.assertEqual(second["target"], ("203.0.113.2", 443))
        self.assertEqual(first["target"], ("203.0.113.1", 53))

    def test_duplicate_endpoint_handle_is_rejected_and_consumed_once(self):
        table = PendingRedirectTableModel()
        args = (51, 90, 17, 6, 4, ("2001:db8::1", 443), ("::1", 41000), 0)
        self.assertTrue(table.insert(*args))
        self.assertFalse(table.insert(*args))
        self.assertIsNotNone(table.take(51, 90, 17, 6, 4, ("::1", 41000), 1))
        self.assertIsNone(table.take(51, 90, 17, 6, 4, ("::1", 41000), 2))

    def test_expired_record_cannot_be_reused(self):
        table = PendingRedirectTableModel()
        self.assertTrue(table.insert(61, 91, 17, 4, 2, ("192.0.2.8", 53),
                                     ("127.0.0.1", 42000), 0))
        self.assertIsNone(table.take(61, 91, 17, 4, 2, ("127.0.0.1", 42000), 31))

    def test_process_exit_removes_all_pending_records_for_pid(self):
        table = PendingRedirectTableModel()
        for handle in (71, 72, 73):
            self.assertTrue(table.insert(handle, 101, 17, 4, 8, ("192.0.2.1", 53),
                                         ("127.0.0.1", 43000 + handle), 0))
        self.assertTrue(table.insert(74, 102, 17, 4, 8, ("192.0.2.2", 53),
                                     ("127.0.0.1", 43074), 0))
        table.process_exit(101)
        for handle in (71, 72, 73):
            self.assertIsNone(table.take(handle, 101, 17, 4, 8,
                                         ("127.0.0.1", 43000 + handle), 1))
        self.assertIsNotNone(table.take(74, 102, 17, 4, 8,
                                        ("127.0.0.1", 43074), 1))


if __name__ == "__main__":
    unittest.main()
