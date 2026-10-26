// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The probe timeout for tests whose probe runs a stand-in (a shell script in the test's folder that answers at once): a
// ceiling, not a measurement. It only bounds a stand-in that hangs; it changes no answer, so no assertion means less.
// 2 or 3 seconds was too tight: on a Mac under load (four suites at once, as the critical-mutant gate runs them, with
// XProtect scanning each new stand-in on its first run) a stand-in's first start took about 5 seconds, a probe timed out,
// and the test failed for a reason that wasn't the code's (24 Oct 2026: on the unmutated code, the python3-and-wget
// container test in test/gaps-0.1.9.test.mjs failed that way in four runs of four, the CERT_REVOKED one in one). Tests
// whose point is a timeout (a host that never answers) keep their own short one.
export const STAND_IN_MS = 60000;
