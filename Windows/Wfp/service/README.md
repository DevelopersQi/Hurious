# WFP management service implementation

The first native service increment owns only the Furious provider and sublayer.
It opens the local BFE engine, creates those objects transactionally and removes
only the Furious-owned provider on teardown.

This is not yet a Windows Service Control Manager executable and does not install
filters. The next increment must add:
1. SCM service lifetime and recovery policy;
2. authenticated, local-only IPC with strict message size/version validation;
3. driver device discovery and ABI negotiation;
4. transactional filter/callout registration and exact cleanup;
5. health reporting and crash/restart reconciliation.

The service must run elevated. Never expose an unauthenticated network listener.
