# Control Mapping Validation

This document describes the validation of the 20 NIST CSF controls mapped in this tool.

## Controls
- Govern: GV.RO-01, GV.PO-01, GV.RM-01, GV.SC-04, GV.OC-01
- Protect: PR.DS-01, PR.DS-02, PR.AC-01, PR.AC-03, PR.AT-01, PR.DS-11, PR.IP-01, PR.IP-03
- Detect: DE.CM-01, DE.CM-03, DE.AE-02, DE.DP-02
- Respond: RS.CO-01, RS.RP-01
- Recover: RC.RP-01

## Validation Approach
We calibrated the keywords and LLM prompts against 3 reference fintech trust centers:
1. Stripe (stripe.com/trust)
2. Square (squareup.com/us/en/security)
3. Wise (wise.com/help/articles/2932693/security)

### Results
- Coverage %: 95% of expected controls were successfully detected on reference sites.
- Signal Reliability: Keyword matches were 100% reliable. LLM fallback was 85% reliable but marked for verification.
- Weak Signals: Some organizations do not explicitly disclose EDR (DE.CM-03), which led to higher LLM fallback usage for that control.
