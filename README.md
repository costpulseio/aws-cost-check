# aws-cost-check

**Find your AWS waste in 60 seconds. Read-only. One file. No agents, no signup.**

```
ESTIMATED ANNUALIZED WASTE                                    $ X,XXX
```

`aws-cost-check` is a single Python script that scans your AWS account with
read-only API calls and prints an estimated annualized waste figure for the
eight most common money leaks:

| # | Check | Why it costs you |
|---|-------|------------------|
| 1 | gp2 → gp3 volumes | gp3 is ~20% cheaper for equal or better baseline performance |
| 2 | Unattached EBS volumes | You pay full price for disks attached to nothing |
| 3 | Idle NAT gateways | ~$33/mo each, even moving zero bytes |
| 4 | Unassociated Elastic IPs | Idle public IPv4s are billed hourly |
| 5 | Stopped instances w/ storage | "We might need it later" has a monthly fee |
| 6 | Underutilized EC2 (<10% CPU, 14d) | Rightsizing candidates hiding in plain sight |
| 7 | Idle RDS (~0 connections, 14d) | Databases nobody has talked to in weeks |
| 8 | Savings Plan coverage gap | Paying on-demand rates for steady-state load |

## Quickstart (easiest: AWS CloudShell)

Open [CloudShell](https://console.aws.amazon.com/cloudshell) — boto3 is preinstalled — then:

```bash
curl -O https://raw.githubusercontent.com/costpulseio/aws-cost-check/main/aws_cost_check.py
python3 aws_cost_check.py
```

Or locally with any read-only profile:

```bash
python3 aws_cost_check.py --profile readonly --regions us-east-1,us-west-2
python3 aws_cost_check.py --json   # pipe it somewhere fun
```

## Permissions

Everything here is covered by the AWS-managed **ViewOnlyAccess** policy, plus
`ce:GetSavingsPlansCoverage` for the coverage check (it skips itself cleanly
if denied). The script never calls a mutating API — grep it, it's one file.

## What the numbers mean

Estimates use typical us-east-1 on-demand pricing and conservative
assumptions. Treat the total as a floor, not an appraisal — real audited
savings usually come in higher once commitment strategy, data transfer, and
architecture-level fixes are on the table.

## Granting access (for audits)

If you're running this as part of a CostPulse audit engagement, use the
Terraform module in [`terraform/costpulse-audit-role.tf`](terraform/costpulse-audit-role.tf)
to create a read-only cross-account IAM role:

```bash
cd terraform
terraform init
terraform apply -var="external_id=<the ID we sent you>"
# Then send us the role_arn output to begin the audit.
```

### External ID handling

The `external_id` variable is a security control that prevents
[confused deputy attacks](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).
A few rules we follow — and you should verify:

- **Unique per client, per engagement.** We generate a new external ID for
  every audit. If you book a second audit later, you get a new ID.
- **Never reused.** Once an engagement closes, that external ID is retired.
- **Never committed.** The external ID is shared out-of-band (email or secure
  link) and must never appear in version control or public docs.
- **Delete the role when done.** Run `terraform destroy` the moment the audit
  is complete. The role has no ongoing value and is a standing attack surface.

## Want the full version?

This script checks 8 patterns. A [CostPulse Cost Audit](https://costpulse.io/audit)
checks dozens more, with exact pricing, risk ratings, remediation Terraform, and a
written guarantee: **3x the fee in identified savings, or it's free.**

And if you just want to know *when* spend goes sideways:
[CostPulse](https://costpulse.io) sends AWS cost anomaly alerts to Slack and
Microsoft Teams.

## License

MIT. PRs welcome — especially new checks with sane savings math.
