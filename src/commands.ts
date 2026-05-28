import path from "node:path";
import { readFile, stat } from "node:fs/promises";
import { Command } from "commander";
import { importFromCdp, saveAndValidate, validateConfig } from "./auth.js";
import { clearConfig, getDisplayConfigPath, resolveConfig } from "./config.js";
import { buildHipaaReport, writeHipaaReportOutput, type HipaaReportOptions } from "./hipaa-report.js";
import { codeError, makeError, ok, printJson } from "./output.js";
import type { OneleetApiClient } from "./oneleet-api.js";
import {
  buildCoverageCheck,
  buildSecurityRemediationQueue,
  buildTrustReadiness,
  buildVendorRiskReport,
  buildWorkforceSummary,
} from "./reports.js";
import {
  clientFor,
  collect,
  configureParserContract,
  getCliVersion,
  jsonRequested,
  parsePositiveInteger,
  parseQueryPairs,
  printFailure,
  render,
  requireConfig,
  runJsonAction,
  tenantIdFor,
  wantsJsonOutput,
  type JsonOptions,
  type TenantOptions,
} from "./cli-runtime.js";
import {
  summarizeAccessReviews,
  summarizeAttackSurfaceIssues,
  summarizeAttackSurfaceScans,
  summarizeCodeRepositories,
  summarizeCodeScan,
  summarizeControls,
  summarizeCurrentUser,
  summarizeDomains,
  summarizeEvidence,
  summarizeFrameworks,
  summarizeIntegrations,
  summarizeMembers,
  summarizeMonitors,
  summarizePentestRequest,
  summarizePolicies,
  summarizeReports,
  summarizeRiskAssessments,
  summarizeSecurityTrainingModules,
  summarizeSecurityTrainingProgress,
  summarizeTenant,
  summarizeTrustConfig,
  summarizeTrustRows,
  summarizeVendors,
} from "./summaries.js";

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("oneleet")
    .description("Agent-first private-surface CLI for Oneleet read workflows")
    .version(getCliVersion())
    .option("--json", "Print JSON envelope for command results and parser errors")
    .configureOutput({
      writeErr: (str) => {
        if (!wantsJsonOutput()) process.stderr.write(str);
      },
    })
    .exitOverride()
    .addHelpText(
      "after",
      `
  Safe first commands:
    oneleet auth status --json
    oneleet doctor --json
    oneleet coverage check --json
    oneleet hipaa report --json
  
  Scenario reports:
    oneleet ops workforce-summary --json
    oneleet vendor-risk report --json
    oneleet trust readiness --json
    oneleet security remediation-queue --json
  
  Raw output warning:
    Prefer summarized defaults. Use --raw or api get --unsafe-raw only for short-lived local debugging.
  `,
    );
  
  const auth = new Command("auth").description("Auth commands");
  auth
    .command("import-cdp")
    .description("Import the oneleet-app session cookie from a logged-in Chrome remote debugging session")
    .option("--host <host>", "CDP host", "127.0.0.1")
    .option("--port <port>", "CDP port", "9333")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions & { host: string; port: string }) => {
      await runJsonAction(async () => {
        const config = await importFromCdp({ host: opts.host, port: Number(opts.port) });
        const saved = await saveAndValidate(config);
        return {
          saved: saved.saved,
          tenantIdConfigured: Boolean(saved.config.tenantId),
          configPath: getDisplayConfigPath(),
          hasOneleetAppCookie: Boolean(saved.config.oneleetAppCookie),
          validation: saved.validation,
        };
      }, opts);
    });
  
  auth
    .command("status")
    .description("Show local auth status")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      const config = await resolveConfig();
      const validation = config.oneleetAppCookie ? await validateConfig(config) : { ok: false, reason: "Missing oneleet-app cookie" };
        const data = {
          hasOneleetAppCookie: Boolean(config.oneleetAppCookie),
          tenantIdConfigured: Boolean(config.tenantId),
          source: config.source,
          configPath: getDisplayConfigPath(),
          validation,
      };
      if (jsonRequested(opts)) printJson(ok(data));
      else printJson(data);
    });
  
  auth
    .command("clear")
    .description("Clear saved Oneleet auth")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      await clearConfig();
      render({ cleared: true }, opts);
    });
  
  program.addCommand(auth);
  
  program
    .command("doctor")
    .description("Validate auth and core Oneleet read endpoints")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions) => {
      try {
        const config = await requireConfig(opts);
        const validation = await validateConfig(config);
        const data = { validation, tenantIdConfigured: Boolean(config.tenantId), configPath: getDisplayConfigPath() };
        if (!validation.ok) {
          const code = validation.errorCode || "CHECK_FAILED";
          const message = validation.reason || "Oneleet doctor checks failed";
          printFailure(makeError(codeError(code, message)), opts, code === "AUTH_INVALID" || code === "AUTH_MISSING" ? 2 : 1);
          return;
        }
        render(data, opts);
      } catch (error: any) {
        const cliError = makeError(error);
        printFailure(cliError, opts, cliError.code === "AUTH_INVALID" || cliError.code === "AUTH_MISSING" ? 2 : 1);
      }
    });
  
  program
    .command("whoami")
    .description("Read the current Oneleet user")
    .option("--raw", "Return full upstream current-user row instead of summarized row")
    .option("--json", "Print JSON envelope")
    .action(async (opts: JsonOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const data = await clientFor(await requireConfig(opts)).getCurrentUser();
        return opts.raw ? data : summarizeCurrentUser(data);
      }, opts);
    });
  
  program
    .command("tenant")
    .description("Tenant commands")
    .addCommand(
      new Command("get")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream tenant row instead of summarized row")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).getTenant(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeTenant(data);
          }, opts);
        }),
    );
  
  program
    .command("dashboard")
    .description("Read Oneleet dashboard summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getDashboard(opts.tenantId || config.tenantId);
      }, opts);
    });
  
  const hipaa = new Command("hipaa").description("HIPAA aggregate commands");
  hipaa
    .command("report")
    .description("Build a read-only HIPAA status report from Oneleet data")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--format <format>", "Output format: json or markdown", "json")
    .option("--out <path>", "Write Markdown report to a file")
    .option("--json", "Print JSON envelope")
    .action(async (opts: HipaaReportOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const tenantId = opts.tenantId || config.tenantId;
        const client = clientFor(config);
        return buildHipaaReport(client, tenantId);
      }, opts, async (report) => writeHipaaReportOutput(report, opts));
    });
  program.addCommand(hipaa);
  
  program
    .command("coverage")
    .description("Adapter coverage and drift checks")
    .addCommand(
      new Command("check")
        .description("Run a sanitized health check across all typed read surfaces")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildCoverageCheck(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  const ops = new Command("ops").description("Operational aggregate reports");
  ops
    .command("workforce-summary")
    .description("Build a sanitized workforce, access-review, training, monitor, and integration follow-up summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return buildWorkforceSummary(clientFor(config), tenantIdFor(opts, config));
      }, opts);
    });
  program.addCommand(ops);
  
  program
    .command("vendor-risk")
    .description("Vendor risk aggregate reports")
    .addCommand(
      new Command("report")
        .description("Build a sanitized vendor-risk, data-inventory, evidence, and privacy/BAA coverage report")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildVendorRiskReport(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  program
    .command("security")
    .description("Security operations aggregate reports")
    .addCommand(
      new Command("remediation-queue")
        .description("Build a sanitized remediation queue across controls, monitors, attack surface, code security, integrations, domains, and pentests")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            return buildSecurityRemediationQueue(clientFor(config), tenantIdFor(opts, config));
          }, opts);
        }),
    );
  
  program
    .command("monitors")
    .description("Monitor commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream monitor rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listMonitors(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeMonitors(data);
          }, opts);
        }),
    );
  
  program
    .command("controls")
    .description("Control commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream control rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listControls(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeControls(data);
          }, opts);
        }),
    );
  
  program
    .command("people")
    .description("People commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream rows instead of summarized people rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listMembers(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeMembers(data);
          }, opts);
        }),
    );
  
  program
    .command("vendors")
    .description("Vendor commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream vendor rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listVendors(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeVendors(data);
          }, opts);
        }),
    );
  
  const evidence = new Command("evidence").description("Evidence commands");
  evidence.addCommand(
    new Command("list")
      .option("--tenant-id <id>", "Tenant id override")
      .option("--raw", "Return full upstream evidence rows instead of summarized rows")
      .option("--json", "Print JSON envelope")
      .action(async (opts: TenantOptions & { raw?: boolean }) => {
        await runJsonAction(async () => {
          const config = await requireConfig(opts);
          const data = await clientFor(config).listEvidence(opts.tenantId || config.tenantId);
          return opts.raw ? data : summarizeEvidence(data);
        }, opts);
      }),
  );
  evidence.addCommand(
    new Command("get")
      .argument("<evidence-id>", "Evidence UUID")
      .option("--json", "Print JSON envelope")
      .action(async (evidenceId: string, opts: JsonOptions) => {
        await runJsonAction(async () => sanitizeEvidence(await clientFor(await requireConfig(opts)).getEvidence(evidenceId)), opts);
      }),
  );
  evidence.addCommand(
    new Command("upload")
      .description("Upload file evidence to a control. Dry-run by default; real writes require --write and --confirm <file-name>.")
      .argument("<file>", "Local evidence file path")
      .requiredOption("--control-id <id>", "Primary control UUID to attach during upload")
      .option("--tenant-id <id>", "Tenant id override")
      .option("--link-control-id <id>", "Additional control UUID to link after upload; repeatable", collect, [])
      .option("--evidence-request-id <id>", "Optional evidence request UUID for the primary control")
      .option("--note <value>", "Optional evidence note")
      .option("--name <file-name>", "Override uploaded evidence file name")
      .option("--type <type>", "Evidence type: auto, FILE, or IMAGE", "auto")
      .option("--reuse-existing-name", "If an evidence item with the same file name exists, link that item instead of uploading a duplicate")
      .option("--write", "Perform the upload/link writes. Without this flag, prints a dry-run preview only.")
      .option("--confirm <file-name>", "Required with --write; must equal the upload file name")
      .option("--json", "Print JSON envelope")
      .action(async (file: string, opts: EvidenceUploadOptions) => {
        await runJsonAction(async () => {
          const upload = await describeEvidenceUpload(file, opts);
          const targetControlIds = uniqueIds([opts.controlId, ...(opts.linkControlId || [])]);
          const plan = {
            dryRun: !opts.write,
            writeRequired: "--write --confirm " + upload.fileName,
            upload: {
              fileName: upload.fileName,
              sizeBytes: upload.sizeBytes,
              type: upload.type,
              primaryControlId: opts.controlId,
              additionalControlIds: targetControlIds.filter((id) => id !== opts.controlId),
              evidenceRequestId: opts.evidenceRequestId || null,
              hasNote: Boolean(opts.note),
              reuseExistingName: Boolean(opts.reuseExistingName),
            },
          };
          if (!opts.write) return plan;
          if (opts.confirm !== upload.fileName) {
            throw codeError("VALIDATION", "--write requires --confirm to exactly match the uploaded file name: " + upload.fileName);
          }

          const config = await requireConfig(opts);
          const tenantId = tenantIdFor(opts, config);
          const client = clientFor(config);
          let evidenceRow: Record<string, unknown> | undefined;
          const actions: Array<Record<string, unknown>> = [];
          if (opts.reuseExistingName) {
            evidenceRow = findEvidenceByFileName(await client.listEvidence(tenantId), upload.fileName);
            if (evidenceRow?.id) actions.push({ action: "reused-existing", evidenceId: evidenceRow.id });
          }
          if (!evidenceRow) {
            const form = buildEvidenceForm(upload, opts);
            evidenceRow = unwrapData(await client.createEvidence(tenantId, form));
            actions.push({ action: "uploaded", evidenceId: evidenceRow.id });
          }

          const evidenceId = stringField(evidenceRow, "id", "created evidence id");
          for (const controlId of targetControlIds) {
            if (controlId === opts.controlId && actions.some((action) => action.action === "uploaded")) {
              actions.push({ action: "linked-during-upload", controlId });
              continue;
            }
            if (hasLinkedId(evidenceRow.controlIds, controlId)) {
              actions.push({ action: "already-linked-control", controlId });
              continue;
            }
            await client.linkEvidenceToControl(evidenceId, {
              controlId,
              ...(opts.evidenceRequestId && controlId === opts.controlId ? { evidenceRequestId: opts.evidenceRequestId } : {}),
            });
            actions.push({ action: "linked-control", controlId });
          }

          const after = unwrapData(await client.getEvidence(evidenceId));
          return {
            ...plan,
            dryRun: false,
            evidence: sanitizeEvidence(after),
            actions,
          };
        }, opts);
      }),
  );
  evidence.addCommand(
    new Command("link-control")
      .description("Link existing evidence to a control. Dry-run by default; real writes require --write and --confirm <evidence-id>.")
      .argument("<evidence-id>", "Evidence UUID")
      .requiredOption("--control-id <id>", "Control UUID")
      .option("--evidence-request-id <id>", "Optional evidence request UUID")
      .option("--write", "Perform the link. Without this flag, prints a dry-run preview only.")
      .option("--confirm <evidence-id>", "Required with --write; must equal the evidence id")
      .option("--json", "Print JSON envelope")
      .action(async (evidenceId: string, opts: EvidenceLinkControlOptions) => {
        await runJsonAction(async () => {
          const patch = { controlId: opts.controlId, ...(opts.evidenceRequestId ? { evidenceRequestId: opts.evidenceRequestId } : {}) };
          if (!opts.write) return { dryRun: true, writeRequired: "--write --confirm " + evidenceId, evidenceId, link: patch };
          if (opts.confirm !== evidenceId) throw codeError("VALIDATION", "--write requires --confirm to exactly match the evidence id.");
          const client = clientFor(await requireConfig(opts));
          await client.linkEvidenceToControl(evidenceId, patch);
          return { dryRun: false, evidence: sanitizeEvidence(unwrapData(await client.getEvidence(evidenceId))), linked: patch };
        }, opts);
      }),
  );
  evidence.addCommand(
    new Command("link-vendor")
      .description("Link existing evidence to a vendor. Dry-run by default; real writes require --write and --confirm <evidence-id>.")
      .argument("<evidence-id>", "Evidence UUID")
      .requiredOption("--vendor-id <id>", "Tenant vendor UUID")
      .option("--write", "Perform the link. Without this flag, prints a dry-run preview only.")
      .option("--confirm <evidence-id>", "Required with --write; must equal the evidence id")
      .option("--json", "Print JSON envelope")
      .action(async (evidenceId: string, opts: EvidenceLinkVendorOptions) => {
        await runJsonAction(async () => {
          const patch = { tenantVendorId: opts.vendorId };
          if (!opts.write) return { dryRun: true, writeRequired: "--write --confirm " + evidenceId, evidenceId, link: patch };
          if (opts.confirm !== evidenceId) throw codeError("VALIDATION", "--write requires --confirm to exactly match the evidence id.");
          const client = clientFor(await requireConfig(opts));
          await client.linkEvidenceToVendor(evidenceId, patch);
          return { dryRun: false, evidence: sanitizeEvidence(unwrapData(await client.getEvidence(evidenceId))), linked: patch };
        }, opts);
      }),
  );
  program.addCommand(evidence);
  
  program
    .command("policies")
    .description("Policy commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream policy rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listPolicies(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizePolicies(data);
          }, opts);
        }),
    )
    .addCommand(
      new Command("types")
        .option("--json", "Print JSON envelope")
        .action(async (opts: JsonOptions) => {
          await runJsonAction(async () => clientFor(await requireConfig(opts)).listPolicyTypes(), opts);
        }),
    );
  
  program
    .command("frameworks")
    .description("Compliance framework commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream framework rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listFrameworks(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeFrameworks(data);
          }, opts);
        }),
    );
  
  program
    .command("access-reviews")
    .description("Access review commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream access-review rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listAccessReviews(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeAccessReviews(data);
          }, opts);
        }),
    );
  
  program
    .command("domains")
    .description("Domain commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream domain rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listDomains(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeDomains(data);
          }, opts);
        }),
    );
  
  program
    .command("integrations")
    .description("Integration commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--include-oneleet-managed <value>", "Include Oneleet-managed integrations", "true")
        .option("--raw", "Return full upstream integration rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { includeOneleetManaged: string; raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listIntegrations(opts.tenantId || config.tenantId, {
              includeOneleetManaged: opts.includeOneleetManaged,
            });
            return opts.raw ? data : summarizeIntegrations(data);
          }, opts);
        }),
    );
  
  program
    .command("risk-assessments")
    .description("Risk assessment commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream risk-assessment rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listRiskAssessments(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeRiskAssessments(data);
          }, opts);
        }),
    );

  const risks = new Command("risks").description("Risk commands");
  risks
    .command("get")
    .argument("<risk-id>", "Risk UUID")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: JsonOptions) => {
      await runJsonAction(async () => sanitizeRisk(await clientFor(await requireConfig(opts)).getRisk(riskId)), opts);
    });
  risks
    .command("update")
    .description("Update a Oneleet risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--title <value>", "Risk title")
    .option("--description <value>", "Risk description")
    .option("--note <value>", "Risk note/rationale")
    .option("--response <value>", "Risk response enum: ACCEPT, MITIGATE, TRANSFER, AVOID")
    .option("--response-details <value>", "Risk response details")
    .option("--category <value>", "Risk category enum")
    .option("--impact <value>", "Impact enum")
    .option("--likelihood <value>", "Likelihood enum")
    .option("--residual-impact <value>", "Residual impact enum")
    .option("--residual-likelihood <value>", "Residual likelihood enum")
    .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id being updated")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskUpdateOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const client = clientFor(config);
        const before = await client.getRisk(riskId);
        const patch = buildRiskPatch(opts);
        if (Object.keys(patch).length === 0) throw codeError("VALIDATION", "No update fields provided.");
        if (!opts.write) {
          return {
            dryRun: true,
            writeRequired: "--write --confirm " + riskId,
            riskId,
            before: sanitizeRisk(before),
            patch,
          };
        }
        if (opts.confirm !== riskId) {
          throw codeError("VALIDATION", "--write requires --confirm to exactly match the risk id.");
        }
        await client.updateRisk(riskId, patch);
        const after = await client.getRisk(riskId);
        return {
          dryRun: false,
          riskId,
          patch,
          before: sanitizeRisk(before),
          after: sanitizeRisk(after),
        };
      }, opts);
    });
  risks
    .command("controls")
    .description("Link or unlink controls on a risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--control-id <id>", "Control UUID to link; repeatable", collect, [])
    .option("--control-title <title>", "Exact control title to link; repeatable", collect, [])
    .option("--unlink-control-id <id>", "Control UUID to unlink; repeatable", collect, [])
    .option("--unlink-control-title <title>", "Exact control title to unlink; repeatable", collect, [])
    .option("--write", "Perform the link/unlink writes. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id being updated")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskControlsOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const tenantId = tenantIdFor(opts, config);
        const client = clientFor(config);
        const before = await client.getRisk(riskId);
        const controls = await resolveRiskControlActions(client, tenantId, opts);
        if (controls.length === 0) throw codeError("VALIDATION", "No control link/unlink fields provided.");
        const patch = { controls: controls.map(({ controlId, link }) => ({ controlId, link })) };
        if (!opts.write) {
          return {
            dryRun: true,
            writeRequired: "--write --confirm " + riskId,
            riskId,
            before: sanitizeRisk(before),
            patch,
            resolvedControls: controls,
          };
        }
        if (opts.confirm !== riskId) throw codeError("VALIDATION", "--write requires --confirm to exactly match the risk id.");
        await client.updateRisk(riskId, patch);
        const after = await client.getRisk(riskId);
        return {
          dryRun: false,
          riskId,
          patch,
          resolvedControls: controls,
          before: sanitizeRisk(before),
          after: sanitizeRisk(after),
        };
      }, opts);
    });
  risks
    .command("archive")
    .description("Archive a risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--write", "Perform the archive. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskArchiveOptions) => {
      await runJsonAction(async () => runRiskArchiveCommand(riskId, opts, "archive"), opts);
    });
  risks
    .command("unarchive")
    .description("Unarchive a risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--write", "Perform the unarchive. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskArchiveOptions) => {
      await runJsonAction(async () => runRiskArchiveCommand(riskId, opts, "unarchive"), opts);
    });
  program.addCommand(risks);
  
  const training = new Command("security-training").description("Security training commands");
  training
    .command("modules")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--include-drafts", "Include drafts")
    .option("--raw", "Return full upstream module rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { includeDrafts?: boolean; raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listSecurityTrainingModules(opts.tenantId || config.tenantId, opts.includeDrafts);
        return opts.raw ? data : summarizeSecurityTrainingModules(data);
      }, opts);
    });
  training
    .command("progress")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream progress rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listSecurityTrainingProgress(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeSecurityTrainingProgress(data);
      }, opts);
    });
  program.addCommand(training);
  
  const trust = new Command("trust").description("Trust center commands");
  trust
    .command("readiness")
    .description("Build a sanitized trust-center and customer-security packet readiness report")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return buildTrustReadiness(clientFor(config), tenantIdFor(opts, config));
      }, opts);
    });
  trust
    .command("config")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream trust config instead of summarized config")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).getTrustConfig(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeTrustConfig(data);
      }, opts);
    });
  for (const [name, method] of [
    ["documents", "listTrustDocuments"],
    ["document-requests", "listTrustDocumentRequests"],
    ["faqs", "listTrustFaqs"],
    ["security-issues", "listTrustSecurityIssues"],
  ] as const) {
    trust
      .command(name)
      .option("--tenant-id <id>", "Tenant id override")
      .option("--raw", "Return full upstream rows instead of summarized rows")
      .option("--json", "Print JSON envelope")
      .action(async (opts: TenantOptions & { raw?: boolean }) => {
        await runJsonAction(async () => {
          const config = await requireConfig(opts);
          const data = await clientFor(config)[method](opts.tenantId || config.tenantId);
          return opts.raw ? data : summarizeTrustRows(data);
        }, opts);
      });
  }
  program.addCommand(trust);
  
  program
    .command("reports")
    .description("Report commands")
    .addCommand(
      new Command("list")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream report rows instead of summarized rows")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).listReports(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizeReports(data);
          }, opts);
        }),
    );
  
  program
    .command("pentests")
    .description("Pentest commands")
    .addCommand(
      new Command("active-request")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream active pentest request instead of summarized result")
        .option("--json", "Print JSON envelope")
        .action(async (opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const data = await clientFor(config).getActivePentestRequest(opts.tenantId || config.tenantId);
            return opts.raw ? data : summarizePentestRequest(data);
          }, opts);
        }),
    );
  
  const codeSecurity = new Command("code-security").description("Code security commands");
  codeSecurity
    .command("scan")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream code-security scan instead of summarized scan")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).getCodeSecurityScan(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeCodeScan(data);
      }, opts);
    });
  codeSecurity
    .command("settings")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getCodeSecuritySettings(opts.tenantId || config.tenantId);
      }, opts);
    });
  codeSecurity
    .command("repositories")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--raw", "Return full upstream code repository rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { raw?: boolean }) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        const data = await clientFor(config).listGitRepositories(opts.tenantId || config.tenantId);
        return opts.raw ? data : summarizeCodeRepositories(data);
      }, opts);
    });
  program.addCommand(codeSecurity);
  
  const attackSurface = new Command("attack-surface").description("Attack surface commands");
  attackSurface
    .command("summary")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions) => {
      await runJsonAction(async () => {
        const config = await requireConfig(opts);
        return clientFor(config).getAttackSurfaceStats(opts.tenantId || config.tenantId);
      }, opts);
    });
  attackSurface
    .command("issues")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--limit <n>", "Limit", "50")
    .option("--raw", "Return full upstream issue rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { limit: string; raw?: boolean }) => {
      await runJsonAction(async () => {
        const limit = parsePositiveInteger(opts.limit, "--limit");
        const config = await requireConfig(opts);
        const data = await clientFor(config).listAttackSurfaceIssues(opts.tenantId || config.tenantId, { limit });
        return opts.raw ? data : summarizeAttackSurfaceIssues(data);
      }, opts);
    });
  attackSurface
    .command("scans")
    .option("--tenant-id <id>", "Tenant id override")
    .option("--limit <n>", "Limit", "50")
    .option("--raw", "Return full upstream scan rows instead of summarized rows")
    .option("--json", "Print JSON envelope")
    .action(async (opts: TenantOptions & { limit: string; raw?: boolean }) => {
      await runJsonAction(async () => {
        const limit = parsePositiveInteger(opts.limit, "--limit");
        const config = await requireConfig(opts);
        const data = await clientFor(config).listAttackSurfaceScans(opts.tenantId || config.tenantId, { limit });
        return opts.raw ? data : summarizeAttackSurfaceScans(data);
      }, opts);
    });
  program.addCommand(attackSurface);
  
  program
    .command("api")
    .description("Unsafe read-only private API escape hatch")
    .addCommand(
      new Command("get")
        .argument("<path>", "GET path under /api/v1")
        .option("--query <key=value...>", "Query parameter", collect, [])
        .option("--unsafe-raw", "Allow raw private API output; may include sensitive data")
        .option("--json", "Print JSON envelope")
        .action(async (path: string, opts: JsonOptions & { query: string[]; unsafeRaw?: boolean }) => {
          await runJsonAction(async () => {
            if (!opts.unsafeRaw) {
              throw codeError("VALIDATION", "api get returns raw private API payloads. Re-run with --unsafe-raw for local debugging only.");
            }
            const config = await requireConfig(opts);
            return clientFor(config).getRaw(path, parseQueryPairs(opts.query));
          }, opts);
        }),
    );
  
    configureParserContract(program);
  return program;
}

type RiskUpdateOptions = JsonOptions & {
  title?: string;
  description?: string;
  note?: string;
  response?: string;
  responseDetails?: string;
  category?: string;
  impact?: string;
  likelihood?: string;
  residualImpact?: string;
  residualLikelihood?: string;
  write?: boolean;
  confirm?: string;
};

type RiskControlsOptions = TenantOptions & {
  controlId?: string[];
  controlTitle?: string[];
  unlinkControlId?: string[];
  unlinkControlTitle?: string[];
  write?: boolean;
  confirm?: string;
};

type RiskArchiveOptions = JsonOptions & {
  write?: boolean;
  confirm?: string;
};

type RiskControlAction = {
  controlId: string;
  title: string | null;
  link: boolean;
  source: string;
};

type EvidenceUploadOptions = TenantOptions & {
  controlId: string;
  linkControlId?: string[];
  evidenceRequestId?: string;
  note?: string;
  name?: string;
  type?: string;
  reuseExistingName?: boolean;
  write?: boolean;
  confirm?: string;
};

type EvidenceLinkControlOptions = JsonOptions & {
  controlId: string;
  evidenceRequestId?: string;
  write?: boolean;
  confirm?: string;
};

type EvidenceLinkVendorOptions = JsonOptions & {
  vendorId: string;
  write?: boolean;
  confirm?: string;
};

type EvidenceUploadDescription = {
  fileName: string;
  sizeBytes: number;
  type: "FILE" | "IMAGE";
  contents: Uint8Array;
};

const ALLOWED_RISK_RESPONSES = new Set(["ACCEPT", "MITIGATE", "TRANSFER", "AVOID"]);
const ALLOWED_RISK_LEVELS = new Set(["MINOR", "MODERATE", "MAJOR"]);
const ALLOWED_RISK_LIKELIHOODS = new Set(["UNLIKELY", "LIKELY", "ALMOST_CERTAIN"]);
const ALLOWED_RISK_CATEGORIES = new Set([
  "SECURITY",
  "OPERATIONAL",
  "FINANCIAL",
  "LEGAL_AND_COMPLIANCE",
  "STRATEGIC_AND_MARKET",
  "FRAUD",
]);

function buildRiskPatch(opts: RiskUpdateOptions): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  setString(patch, "title", opts.title);
  setString(patch, "description", opts.description);
  setString(patch, "note", opts.note);
  setString(patch, "responseDetails", opts.responseDetails);
  setEnum(patch, "response", opts.response, ALLOWED_RISK_RESPONSES);
  setEnum(patch, "category", opts.category, ALLOWED_RISK_CATEGORIES);
  setEnum(patch, "impact", opts.impact, ALLOWED_RISK_LEVELS);
  setEnum(patch, "residualImpact", opts.residualImpact, ALLOWED_RISK_LEVELS);
  setEnum(patch, "likelihood", opts.likelihood, ALLOWED_RISK_LIKELIHOODS);
  setEnum(patch, "residualLikelihood", opts.residualLikelihood, ALLOWED_RISK_LIKELIHOODS);
  return patch;
}

function setString(target: Record<string, unknown>, key: string, value: string | undefined): void {
  if (value === undefined) return;
  const trimmed = value.trim();
  if (!trimmed) throw codeError("VALIDATION", `--${kebab(key)} cannot be empty.`);
  target[key] = trimmed;
}

function setEnum(target: Record<string, unknown>, key: string, value: string | undefined, allowed: Set<string>): void {
  if (value === undefined) return;
  const normalized = value.trim().toUpperCase().replace(/-/g, "_");
  if (!allowed.has(normalized)) {
    throw codeError("VALIDATION", `Invalid --${kebab(key)} value. Allowed: ${Array.from(allowed).join(", ")}.`);
  }
  target[key] = normalized;
}

function kebab(value: string): string {
  return value.replace(/[A-Z]/g, (match) => "-" + match.toLowerCase());
}

function sanitizeRisk(value: unknown): Record<string, unknown> {
  const row = unwrapData(value);
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    note: row.note,
    category: row.category,
    impact: row.impact,
    likelihood: row.likelihood,
    rating: row.rating,
    response: row.response,
    responseDetails: row.responseDetails,
    residualImpact: row.residualImpact,
    residualLikelihood: row.residualLikelihood,
    residualRating: row.residualRating,
    controls: Array.isArray(row.controls)
      ? row.controls.map((control) => {
          const c = control && typeof control === "object" ? (control as Record<string, unknown>) : {};
          return {
            id: typeof c.id === "string" ? c.id : null,
            title: controlTitleOf(c),
            status: typeof c.status === "string" ? c.status : null,
          };
        })
      : [],
    updatedAt: row.updatedAt,
  };
}

async function resolveRiskControlActions(
  client: OneleetApiClient,
  tenantId: string,
  opts: RiskControlsOptions,
): Promise<RiskControlAction[]> {
  const actions: RiskControlAction[] = [];
  for (const controlId of opts.controlId || []) {
    addRiskControlAction(actions, {
      controlId: requireUuid(controlId, "control id"),
      title: null,
      link: true,
      source: "control-id",
    });
  }
  for (const controlId of opts.unlinkControlId || []) {
    addRiskControlAction(actions, {
      controlId: requireUuid(controlId, "unlink control id"),
      title: null,
      link: false,
      source: "unlink-control-id",
    });
  }

  const linkTitles = opts.controlTitle || [];
  const unlinkTitles = opts.unlinkControlTitle || [];
  if (linkTitles.length || unlinkTitles.length) {
    const controls = rowsOf(await client.listControls(tenantId));
    for (const title of linkTitles) {
      const control = resolveControlByTitle(controls, title, "--control-title");
      addRiskControlAction(actions, {
        controlId: control.controlId,
        title: control.title,
        link: true,
        source: "control-title",
      });
    }
    for (const title of unlinkTitles) {
      const control = resolveControlByTitle(controls, title, "--unlink-control-title");
      addRiskControlAction(actions, {
        controlId: control.controlId,
        title: control.title,
        link: false,
        source: "unlink-control-title",
      });
    }
  }

  return actions;
}

function addRiskControlAction(actions: RiskControlAction[], action: RiskControlAction): void {
  const existing = actions.find((candidate) => candidate.controlId.toLowerCase() === action.controlId.toLowerCase());
  if (existing && existing.link !== action.link) {
    throw codeError("VALIDATION", `Control ${action.controlId} cannot be both linked and unlinked in the same command.`);
  }
  if (existing) return;
  actions.push(action);
}

function resolveControlByTitle(
  controls: unknown[],
  requestedTitle: string,
  flagName: string,
): { controlId: string; title: string } {
  const normalizedRequest = normalizeTitle(requestedTitle);
  if (!normalizedRequest) throw codeError("VALIDATION", `${flagName} cannot be empty.`);
  const matches = controls
    .map((control) => (control && typeof control === "object" ? (control as Record<string, unknown>) : null))
    .filter((control): control is Record<string, unknown> => Boolean(control))
    .map((control) => ({ row: control, title: controlTitleOf(control) }))
    .filter((control) => control.title && normalizeTitle(control.title) === normalizedRequest);

  if (matches.length === 0) throw codeError("VALIDATION", `No control title matched "${requestedTitle}".`);
  if (matches.length > 1) {
    throw codeError("VALIDATION", `Control title "${requestedTitle}" matched ${matches.length} controls; use --control-id instead.`);
  }
  return {
    controlId: stringField(matches[0].row, "id", "control id"),
    title: matches[0].title || requestedTitle.trim(),
  };
}

function normalizeTitle(value: string | null): string {
  return (value || "").trim().replace(/\s+/g, " ").toLowerCase();
}

function controlTitleOf(row: Record<string, unknown>): string | null {
  if (typeof row.title === "string" && row.title.trim()) return row.title;
  for (const key of ["controlType", "control", "metadata"]) {
    const nested = row[key];
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      const title = (nested as Record<string, unknown>).title;
      if (typeof title === "string" && title.trim()) return title;
    }
  }
  return null;
}

async function runRiskArchiveCommand(riskId: string, opts: RiskArchiveOptions, action: "archive" | "unarchive"): Promise<Record<string, unknown>> {
  requireUuid(riskId, "risk id");
  const client = clientFor(await requireConfig(opts));
  const before = await client.getRisk(riskId);
  if (!opts.write) {
    return {
      dryRun: true,
      writeRequired: "--write --confirm " + riskId,
      riskId,
      action,
      before: sanitizeRisk(before),
    };
  }
  if (opts.confirm !== riskId) throw codeError("VALIDATION", "--write requires --confirm to exactly match the risk id.");
  const result = action === "archive" ? await client.archiveRisk(riskId) : await client.unarchiveRisk(riskId);
  return {
    dryRun: false,
    riskId,
    action,
    result: summarizeMutationResult(result),
    before: sanitizeRisk(before),
    after: await getRiskAfterMutation(client, riskId),
  };
}

async function getRiskAfterMutation(client: OneleetApiClient, riskId: string): Promise<Record<string, unknown>> {
  try {
    return sanitizeRisk(await client.getRisk(riskId));
  } catch (error: any) {
    const cliError = makeError(error);
    return {
      unavailable: true,
      error: {
        code: cliError.code,
        message: cliError.message,
      },
    };
  }
}

function summarizeMutationResult(value: unknown): Record<string, unknown> {
  const row = unwrapData(value);
  if (!Object.keys(row).length) return { ok: true };
  return {
    ok: true,
    id: typeof row.id === "string" ? row.id : null,
    archived: typeof row.archived === "boolean" ? row.archived : typeof row.isArchived === "boolean" ? row.isArchived : null,
    status: typeof row.status === "string" ? row.status : null,
  };
}

async function describeEvidenceUpload(file: string, opts: EvidenceUploadOptions): Promise<EvidenceUploadDescription> {
  const fileInfo = await stat(file).catch((error) => {
    throw codeError("VALIDATION", `Cannot read evidence file: ${error?.message || file}`);
  });
  if (!fileInfo.isFile()) throw codeError("VALIDATION", "Evidence path must be a file.");
  const fileName = (opts.name || path.basename(file)).trim();
  if (!fileName) throw codeError("VALIDATION", "Evidence file name cannot be empty.");
  if (fileName.includes("/") || fileName.includes("\\")) throw codeError("VALIDATION", "--name must be a file name, not a path.");
  if (opts.evidenceRequestId) requireUuid(opts.evidenceRequestId, "evidence request id");
  requireUuid(opts.controlId, "control id");
  for (const controlId of opts.linkControlId || []) requireUuid(controlId, "link control id");
  const contents = new Uint8Array(await readFile(file));
  return {
    fileName,
    sizeBytes: fileInfo.size,
    type: evidenceUploadType(opts.type, fileName),
    contents,
  };
}

function buildEvidenceForm(upload: EvidenceUploadDescription, opts: EvidenceUploadOptions): FormData {
  const form = new FormData();
  form.append("type", upload.type);
  form.append("controlId", opts.controlId);
  if (opts.evidenceRequestId) form.append("evidenceRequestId", opts.evidenceRequestId);
  if (opts.note?.trim()) form.append("note", opts.note.trim());
  form.append("upload", new Blob([copyToArrayBuffer(upload.contents)], { type: contentTypeForFile(upload.fileName) }), upload.fileName);
  return form;
}

function copyToArrayBuffer(contents: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(contents.byteLength);
  new Uint8Array(copy).set(contents);
  return copy;
}

function evidenceUploadType(value: string | undefined, fileName: string): "FILE" | "IMAGE" {
  const normalized = (value || "auto").trim().toUpperCase();
  if (normalized === "AUTO") return isImageFileName(fileName) ? "IMAGE" : "FILE";
  if (normalized === "FILE" || normalized === "IMAGE") return normalized;
  throw codeError("VALIDATION", "--type must be auto, FILE, or IMAGE.");
}

function contentTypeForFile(fileName: string): string {
  const extension = path.extname(fileName).toLowerCase();
  if (extension === ".csv") return "text/csv";
  if (extension === ".json") return "application/json";
  if (extension === ".md" || extension === ".txt") return "text/plain";
  if (extension === ".pdf") return "application/pdf";
  if (extension === ".png") return "image/png";
  if (extension === ".jpg" || extension === ".jpeg") return "image/jpeg";
  if (extension === ".gif") return "image/gif";
  if (extension === ".webp") return "image/webp";
  return "application/octet-stream";
}

function isImageFileName(fileName: string): boolean {
  return [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".svg"].includes(path.extname(fileName).toLowerCase());
}

function findEvidenceByFileName(value: unknown, fileName: string): Record<string, unknown> | undefined {
  return rowsOf(value).find((row) => row && typeof row === "object" && (row as Record<string, unknown>).fileName === fileName) as
    | Record<string, unknown>
    | undefined;
}

function rowsOf(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  const row = value as Record<string, unknown>;
  if (Array.isArray(row.rows)) return row.rows;
  if (row.data && typeof row.data === "object" && Array.isArray((row.data as Record<string, unknown>).rows)) {
    return (row.data as Record<string, unknown>).rows as unknown[];
  }
  if (Array.isArray(row.data)) return row.data;
  return [];
}

function unwrapData(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && "data" in value) {
    const data = (value as Record<string, unknown>).data;
    if (data && typeof data === "object" && !Array.isArray(data)) return data as Record<string, unknown>;
  }
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function uniqueIds(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    const normalized = requireUuid(id, "id");
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function requireUuid(value: string | undefined, label: string): string {
  const candidate = (value || "").trim();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(candidate)) return candidate;
  throw codeError("VALIDATION", `Invalid ${label}. Expected a UUID.`);
}

function hasLinkedId(value: unknown, id: string): boolean {
  return Array.isArray(value) && value.includes(id);
}

function stringField(row: Record<string, unknown>, key: string, label: string): string {
  const value = row[key];
  if (typeof value === "string" && value.trim()) return value;
  throw codeError("UPSTREAM_SHAPE", `Missing ${label} in Oneleet response.`);
}

function sanitizeEvidence(value: unknown): Record<string, unknown> {
  const row = unwrapData(value);
  return {
    id: row.id,
    type: row.type || null,
    fileName: row.fileName || null,
    name: row.name || null,
    link: row.link ? "[present]" : null,
    aiReviewStatus: row.aiReviewStatus || null,
    controlIds: Array.isArray(row.controlIds) ? row.controlIds : [],
    vendorIds: Array.isArray(row.vendorIds) ? row.vendorIds : [],
    controlCount: Array.isArray(row.controlIds) ? row.controlIds.length : 0,
    vendorCount: Array.isArray(row.vendorIds) ? row.vendorIds.length : 0,
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
  };
}
