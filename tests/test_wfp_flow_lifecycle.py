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


if __name__ == "__main__":
    unittest.main()
