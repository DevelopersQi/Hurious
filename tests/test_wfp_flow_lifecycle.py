import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = (ROOT / "Windows/Wfp/driver/FuriousWfpCallout.c").read_text(encoding="utf-8")
ENGINE = (ROOT / "Windows/Wfp/service/WfpEngine.cpp").read_text(encoding="utf-8")


class WfpFlowLifecycleContractTests(unittest.TestCase):
    def test_v4_v6_flow_callouts_are_registered(self):
        self.assertIn("FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT", DRIVER)
        self.assertIn("FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT", DRIVER)
        self.assertIn("FURIOUS_WFP_CALLOUT_COUNT 4", DRIVER)
        self.assertIn("FuriousFlowEstablishedClassify", DRIVER)

    def test_real_flow_identity_and_policy_generation_are_associated(self):
        self.assertIn("FWPS_METADATA_FIELD_FLOW_HANDLE", DRIVER)
        self.assertIn("FWPS_METADATA_FIELD_PROCESS_ID", DRIVER)
        self.assertIn("context->FlowId = inMetaValues->flowHandle", DRIVER)
        self.assertIn("context->ProcessId = (ULONG)inMetaValues->processId", DRIVER)
        self.assertIn("context->PolicyGeneration = endpoint.PolicyGeneration", DRIVER)
        self.assertIn("FwpsFlowAssociateContext0(", DRIVER)

    def test_duplicate_association_does_not_replace_existing_context(self):
        self.assertIn("status == STATUS_OBJECT_NAME_EXISTS", DRIVER)
        duplicate = DRIVER.split("status == STATUS_OBJECT_NAME_EXISTS", 1)[1][:500]
        self.assertIn("ExFreePoolWithTag(context", duplicate)
        self.assertNotIn("FwpsFlowRemoveContext0", duplicate)

    def test_flow_delete_releases_associated_context(self):
        self.assertIn("static VOID NTAPI FuriousFlowDelete(", DRIVER)
        callback = DRIVER.split("static VOID NTAPI FuriousFlowDelete(", 1)[1].split(
            "static VOID FuriousUnload", 1
        )[0]
        self.assertIn("FURIOUS_WFP_FLOW_CONTEXT_MAGIC", callback)
        self.assertIn("ExFreePoolWithTag(context, FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG)", callback)

    def test_process_exit_invalidates_broker_and_os_flow_teardown_owns_flow_delete(self):
        notify = DRIVER.split("static VOID NTAPI FuriousProcessNotify(", 1)[1].split(
            "static ULONG FuriousGetDriverFlags", 1
        )[0]
        self.assertIn("gEndpointConfig.ProxyProcessId == processIdValue", notify)
        self.assertIn("PsSetCreateProcessNotifyRoutineEx", DRIVER)
        # Flow contexts are owned by WFP and released by flowDeleteFn as
        # process teardown closes the process' endpoints; no PID-based free
        # races an in-flight classify callback.
        self.assertIn("FwpsFlowAssociateContext0(", DRIVER)
        self.assertIn("FuriousFlowDelete", DRIVER)

    def test_management_filters_cover_both_flow_established_layers(self):
        self.assertIn("FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4", ENGINE)
        self.assertIn("FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6", ENGINE)
        self.assertIn("kFlowEstablishedV4CalloutKey", ENGINE)
        self.assertIn("kFlowEstablishedV6CalloutKey", ENGINE)
        self.assertIn("FWP_ACTION_CALLOUT_INSPECTION", ENGINE)
        self.assertIn("FWPM_CONDITION_ALE_ORIGINAL_APP_ID", ENGINE)
        self.assertIn("expectedAppCondition", ENGINE)

    def test_udp_proxy_rules_install_flow_filters_and_cleanup_recognizes_them(self):
        self.assertIn("protocol == 17 && rule.Action == FuriousWfpActionProxy", ENGINE)
        self.assertIn("&kFlowEstablishedV4CalloutKey", ENGINE)
        self.assertIn("&kFlowEstablishedV6CalloutKey", ENGINE)
        self.assertIn("const GUID* calloutKeys[]", ENGINE)
        self.assertIn("&kFlowEstablishedV4CalloutKey, &kFlowEstablishedV6CalloutKey", ENGINE)


if __name__ == "__main__":
    unittest.main()
