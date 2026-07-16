import path from "node:path";
import { readFile, stat } from "node:fs/promises";
import { Command } from "commander";
import { importFromCdp, saveAndValidate, validateConfig } from "./auth.js";
import { clearConfig, getDisplayConfigPath, resolveConfig } from "./config.js";
import { buildHipaaReport, writeHipaaReportOutput, type HipaaReportOptions } from "./hipaa-report.js";
import { codeError, makeError, ok, printJson } from "./output.js";
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
  summarizeControlChecks,
  summarizeControlFeedback,
  summarizeControls,
  summarizeCurrentUser,
  summarizeDomains,
  summarizeEvidence,
  summarizeFrameworks,
  summarizeIntegrations,
  summarizeMonitorRow,
  summarizeMembers,
  summarizeMonitorControls,
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
    )
    .addCommand(
      new Command("get")
        .argument("<monitor>", "Monitor UUID or local ref from `monitors list`, for example monitor-080")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream monitor detail instead of a sanitized detail")
        .option("--json", "Print JSON envelope")
        .action(async (monitor: string, opts: TenantOptions & { raw?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const client = clientFor(config);
            const target = await resolveMonitorSelector(client, tenantIdFor(opts, config), monitor);
            const data = await client.getMonitor(target.id);
            return opts.raw ? data : sanitizeMonitor(data);
          }, opts);
        }),
    )
    .addCommand(
      new Command("controls")
        .argument("<monitor>", "Monitor UUID or local ref from `monitors list`, for example monitor-080")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream linked-control rows instead of summarized rows")
        .option("--show-ids", "Include raw control IDs for follow-up writes")
        .option("--json", "Print JSON envelope")
        .action(async (monitor: string, opts: TenantOptions & { raw?: boolean; showIds?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const client = clientFor(config);
            const target = await resolveMonitorSelector(client, tenantIdFor(opts, config), monitor);
            const data = await client.listMonitorControls(target.id);
            return opts.raw ? data : summarizeMonitorControls(data, { showIds: Boolean(opts.showIds) });
          }, opts);
        }),
    )
    .addCommand(
      new Command("rerun")
        .description("Trigger a monitor rerun. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .option("--write", "Perform the rerun. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorWriteOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const plan = { dryRun: !opts.write, writeRequired: "--write --confirm " + normalizedMonitorId, monitorId: normalizedMonitorId, action: "rerun" };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.rerunMonitor(normalizedMonitorId);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("set-enabled")
        .description("Enable or disable a monitor. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .requiredOption("--enabled <true|false>", "Desired enabled state")
        .option("--disabled-reason <value>", "Required by Oneleet UI flow when disabling")
        .option("--review-remind-at <iso-date>", "Optional review reminder timestamp when disabling")
        .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorSetEnabledOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const patch = buildMonitorEnabledPatch(opts);
            const plan = {
              dryRun: !opts.write,
              writeRequired: "--write --confirm " + normalizedMonitorId,
              monitorId: normalizedMonitorId,
              patch,
            };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.updateMonitorEnabled(normalizedMonitorId, patch);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("snooze")
        .description("Snooze a monitor. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .requiredOption("--until <iso-date>", "Snooze until timestamp")
        .option("--reason <value>", "Snooze reason")
        .option("--write", "Perform the snooze. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorSnoozeOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const patch = buildMonitorSnoozePatch(opts);
            const plan = { dryRun: !opts.write, writeRequired: "--write --confirm " + normalizedMonitorId, monitorId: normalizedMonitorId, patch };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.snoozeMonitor(normalizedMonitorId, patch);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("unsnooze")
        .description("Unsnooze a monitor. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .option("--write", "Perform the unsnooze. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorWriteOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const plan = { dryRun: !opts.write, writeRequired: "--write --confirm " + normalizedMonitorId, monitorId: normalizedMonitorId, action: "unsnooze" };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.unsnoozeMonitor(normalizedMonitorId);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("set-config")
        .description("Patch monitor configuration JSON. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .requiredOption("--config-json <json>", "JSON object body accepted by Oneleet monitor config")
        .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorSetConfigOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const patch = parseJsonObjectOption(opts.configJson, "--config-json");
            const plan = { dryRun: !opts.write, writeRequired: "--write --confirm " + normalizedMonitorId, monitorId: normalizedMonitorId, patch };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.updateMonitorConfig(normalizedMonitorId, patch);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("update-assets-ignore-status")
        .description("Ignore or unignore monitor assets. Dry-run by default; real writes require --write and --confirm <monitor-id>.")
        .argument("<monitor-id>", "Monitor UUID")
        .option("--ignore-asset-id <id>", "Asset instance UUID to ignore; repeatable", collect, [])
        .option("--unignore-asset-id <id>", "Asset instance UUID to re-monitor; repeatable", collect, [])
        .option("--reason <value>", "Reason to apply to newly ignored assets")
        .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
        .option("--confirm <monitor-id>", "Required with --write; must equal the monitor id")
        .option("--json", "Print JSON envelope")
        .action(async (monitorId: string, opts: MonitorAssetIgnoreOptions) => {
          await runJsonAction(async () => {
            const normalizedMonitorId = requireUuid(monitorId, "monitor id");
            const patch = buildMonitorAssetIgnorePatch(opts);
            const plan = { dryRun: !opts.write, writeRequired: "--write --confirm " + normalizedMonitorId, monitorId: normalizedMonitorId, patch };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, normalizedMonitorId);
            const client = clientFor(await requireConfig(opts));
            await client.updateMonitorAssetsIgnoreStatus(normalizedMonitorId, patch);
            return { ...plan, dryRun: false, monitor: sanitizeMonitor(unwrapData(await client.getMonitor(normalizedMonitorId))) };
          }, opts);
        }),
    )
    .addCommand(
      new Command("refresh")
        .argument("<monitor>", "Local monitor ref from `monitors list`, for example monitor-014")
        .description("Trigger a Oneleet monitor rerun using a safe local monitor ref")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--wait <seconds>", "Poll for a completed latest run for up to N seconds", "0")
        .option("--json", "Print JSON envelope")
        .action(async (monitor: string, opts: TenantOptions & { wait: string }) => {
          await runJsonAction(async () => {
            const waitSeconds = parseWaitSeconds(opts.wait);
            const config = await requireConfig(opts);
            const tenantId = tenantIdFor(opts, config);
            const client = clientFor(config);
            const monitorRows = rowsFromMonitorList(await client.listMonitors(tenantId));
            const target = resolveMonitorForRefresh(monitor, monitorRows);
            if (target.row?.monitorType?.rerunDisabled === true) {
              throw codeError("CHECK_FAILED", "This monitor type reports rerunDisabled=true.");
            }

            const beforeRunKey = monitorRunKey(target.row);
            await client.rerunMonitor(target.id);

            const waitStartedAt = Date.now();
            const waitResult = await readMonitorAfterRefresh(client, tenantId, target.id, beforeRunKey, waitSeconds);
            const afterRow = waitResult.row || target.row;
            const afterIndex = waitResult.index ?? target.index;

            return {
              triggered: true,
              selector: {
                mode: "ref",
                ref: target.ref,
                hasId: true,
              },
              wait: {
                requestedSeconds: waitSeconds,
                completed: waitResult.completed,
                reason: waitResult.reason,
                elapsedSeconds: Math.round((Date.now() - waitStartedAt) / 1000),
              },
              before: summarizeMonitorRow(target.row, target.index),
              after: summarizeMonitorRow(afterRow, afterIndex),
            };
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
    )
    .addCommand(
      new Command("checks")
        .description("List monitor/manual checks attached to a control")
        .argument("<control>", "Control UUID or local ref from `controls list`, for example control-044")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--raw", "Return full upstream check rows instead of summarized rows")
        .option("--show-ids", "Include raw check and monitor IDs for follow-up writes")
        .option("--json", "Print JSON envelope")
        .action(async (control: string, opts: TenantOptions & { raw?: boolean; showIds?: boolean }) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const client = clientFor(config);
            const target = await resolveControlSelector(client, tenantIdFor(opts, config), control);
            const data = await client.listControlChecks(target.id);
            return opts.raw ? data : summarizeControlChecks(data, { showIds: Boolean(opts.showIds) });
          }, opts);
        }),
    )
    .addCommand(
      new Command("feedback")
        .description("Traverse matching controls and return sanitized reviewer feedback and evidence-request details")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--status <status>", "Control status to include; repeatable. Defaults to NEEDS_CHANGES. Use ALL to disable status filtering.", collect, [])
        .option("--limit <n>", "Maximum matching controls to traverse", "100")
        .option("--show-ids", "Include raw control and evidence-request IDs for follow-up writes")
        .option("--json", "Print JSON envelope")
        .action(async (opts: ControlFeedbackOptions) => {
          await runJsonAction(async () => {
            const limit = parsePositiveInteger(opts.limit, "--limit");
            const statuses = normalizeControlFeedbackStatuses(opts.status);
            const config = await requireConfig(opts);
            const client = clientFor(config);
            const controls = rowsOf(await client.listControls(opts.tenantId || config.tenantId)) as Record<string, unknown>[];
            const matching = controls.filter((row) => !statuses || statuses.has(String(row.status || "").toUpperCase()));
            const selected = matching.slice(0, limit);
            const details = await Promise.all(selected.map((row) => client.getControl(stringField(row, "id", "control id"))));
            return {
              statusFilter: statuses ? Array.from(statuses).sort() : ["ALL"],
              totalMatching: matching.length,
              returned: details.length,
              truncated: matching.length > details.length,
              rows: details.map((row, index) => summarizeControlFeedback(row, index, { showIds: Boolean(opts.showIds) })),
            };
          }, opts);
        }),
    )
    .addCommand(
      new Command("request-review")
        .description("Request Oneleet review for a control. Dry-run by default; real writes require exact selector confirmation.")
        .argument("<control>", "Control UUID or local ref from `controls list`, for example control-044")
        .option("--tenant-id <id>", "Tenant id override")
        .option("--write", "Perform the review request. Without this flag, prints a dry-run preview only.")
        .option("--confirm <control>", "Required with --write; must exactly equal the supplied control selector")
        .option("--json", "Print JSON envelope")
        .action(async (control: string, opts: ControlReviewWriteOptions) => {
          await runJsonAction(async () => {
            const config = isUuid(control) ? null : await requireConfig(opts);
            const client = config ? clientFor(config) : null;
            const target = client
              ? await resolveControlSelector(client, tenantIdFor(opts, config!), control)
              : { id: requireUuid(control, "control id"), ref: null, row: null, index: null };
            const plan = {
              dryRun: !opts.write,
              writeRequired: "--write --confirm " + control,
              ...(target.ref
                ? { selector: { mode: "ref", ref: target.ref, hasId: true } }
                : { controlId: target.id, selector: { mode: "id", hasId: true } }),
              action: "request-review",
            };
            if (!opts.write) return plan;
            requireWriteConfirmation(opts.confirm, control, "control selector");
            const writeClient = client || clientFor(await requireConfig(opts));
            await writeClient.requestControlReview(target.id);
            const after = unwrapData(await writeClient.getControl(target.id));
            return {
              ...plan,
              dryRun: false,
              control: summarizeControlFeedback(after, 0, { showIds: true }),
            };
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
    )
    .addCommand(
      new Command("set-audience")
        .description("Set a policy's signature audience. Dry-run by default; real writes require --write and --confirm <policy-id>.")
        .argument("<policy-id>", "Policy UUID")
        .option("--audience <value>", "Audience enum: EVERYONE, EMPLOYEES, CONTRACTORS, GROUPS")
        .option("--group-id <id>", "Group UUID to include (only with --audience GROUPS); repeatable. Omit all to require no signers.", collect, [])
        .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
        .option("--confirm <policy-id>", "Required with --write; must equal the policy id being updated")
        .option("--json", "Print JSON envelope")
        .action(async (policyId: string, opts: PolicySetAudienceOptions) => {
          await runJsonAction(async () => {
            const config = await requireConfig(opts);
            const client = clientFor(config);
            const before = unwrapData(await client.getPolicy(policyId));
            const patch = buildPolicyAudiencePatch(opts);
            if (!opts.write) {
              return {
                dryRun: true,
                writeRequired: "--write --confirm " + policyId,
                policyId,
                before: sanitizePolicy(before),
                patch,
              };
            }
            if (opts.confirm !== policyId) {
              throw codeError("VALIDATION", "--write requires --confirm to exactly match the policy id.");
            }
            await client.updatePolicy(policyId, patch);
            const after = unwrapData(await client.getPolicy(policyId));
            return {
              dryRun: false,
              policyId,
              patch,
              before: sanitizePolicy(before),
              after: sanitizePolicy(after),
            };
          }, opts);
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
    )
    .addCommand(
      new Command("mark-empty-vendors-reviewed")
        .description("Mark pending access-review vendors with no detected accounts as reviewed. Dry-run by default.")
        .argument("<access-review-id>", "Access review UUID")
        .option("--note <value>", "Reviewer note to attach to each mark-as-reviewed action")
        .option("--show-ids", "Include access-review vendor IDs in target summaries")
        .option("--write", "Perform the updates. Without this flag, prints a dry-run preview only.")
        .option("--confirm <access-review-id>", "Required with --write; must equal the access review id")
        .option("--json", "Print JSON envelope")
        .action(async (accessReviewId: string, opts: AccessReviewMarkEmptyVendorsOptions) => {
          await runJsonAction(async () => {
            const normalizedAccessReviewId = requireUuid(accessReviewId, "access review id");
            const note = accessReviewMarkReviewedNote(opts);
            const client = clientFor(await requireConfig(opts));
            const before = unwrapData(await client.getAccessReview(normalizedAccessReviewId));
            const selection = selectEmptyAccessReviewVendors(before);
            const plan = describeEmptyAccessReviewVendorSelection(before, normalizedAccessReviewId, selection, note, Boolean(opts.showIds));

            if (!opts.write) return { ...plan, dryRun: true, writeRequired: "--write --confirm " + normalizedAccessReviewId };
            if (opts.confirm !== normalizedAccessReviewId) {
              throw codeError("VALIDATION", "--write requires --confirm to exactly match the access review id.");
            }

            for (const target of selection.targets) {
              await client.markAccessReviewVendorReviewed(target.id, buildAccessReviewMarkReviewedForm(note));
            }

            const after = unwrapData(await client.getAccessReview(normalizedAccessReviewId));
            const afterSelection = selectEmptyAccessReviewVendors(after);
            return {
              ...plan,
              dryRun: false,
              writtenCount: selection.targets.length,
              after: describeEmptyAccessReviewVendorSelection(after, normalizedAccessReviewId, afterSelection, note, Boolean(opts.showIds)),
            };
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
    .command("archive")
    .description("Archive a Oneleet risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--write", "Perform the archive. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id being archived")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskArchiveOptions) => {
      await runJsonAction(async () => {
        requireUuid(riskId, "risk id");
        const config = await requireConfig(opts);
        const client = clientFor(config);
        const before = await client.getRisk(riskId);
        if (!opts.write) {
          return {
            dryRun: true,
            writeRequired: "--write --confirm " + riskId,
            riskId,
            before: sanitizeRisk(before),
          };
        }
        if (opts.confirm !== riskId) {
          throw codeError("VALIDATION", "--write requires --confirm to exactly match the risk id.");
        }
        const result = await client.archiveRisk(riskId);
        const after = await client.getRisk(riskId).catch(() => null);
        return {
          dryRun: false,
          riskId,
          result,
          before: sanitizeRisk(before),
          after: after ? sanitizeRisk(after) : null,
        };
      }, opts);
    });
  risks
    .command("link-controls")
    .description("Append control links to a Oneleet risk. Dry-run by default; real writes require --write and --confirm <risk-id>.")
    .argument("<risk-id>", "Risk UUID")
    .option("--control-id <id>", "Control UUID to link; repeatable", collect, [])
    .option("--replace", "Replace existing risk control links instead of appending")
    .option("--write", "Perform the update. Without this flag, prints a dry-run preview only.")
    .option("--confirm <risk-id>", "Required with --write; must equal the risk id being updated")
    .option("--json", "Print JSON envelope")
    .action(async (riskId: string, opts: RiskLinkControlsOptions) => {
      await runJsonAction(async () => {
        requireUuid(riskId, "risk id");
        const controlIds = uniqueUuidList(opts.controlId || [], "control id");
        if (controlIds.length === 0) throw codeError("VALIDATION", "Provide at least one --control-id.");
        const config = await requireConfig(opts);
        const client = clientFor(config);
        const before = await client.getRisk(riskId);
        const beforeRow = unwrapData(before);
        const existingControlIds = opts.replace ? [] : controlIdsOfRisk(beforeRow);
        const nextControlIds = uniqueIds([...existingControlIds, ...controlIds]);
        const patch = { controls: nextControlIds.map((id) => ({ id })) };
        const summary = {
          addedControlIds: controlIds.filter((id) => !existingControlIds.includes(id)),
          existingControlCount: existingControlIds.length,
          nextControlCount: nextControlIds.length,
          replace: Boolean(opts.replace),
        };
        if (!opts.write) {
          return {
            dryRun: true,
            writeRequired: "--write --confirm " + riskId,
            riskId,
            summary,
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
          summary,
          before: sanitizeRisk(before),
          after: sanitizeRisk(after),
        };
      }, opts);
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

type PolicySetAudienceOptions = JsonOptions & {
  audience?: string;
  groupId?: string[];
  write?: boolean;
  confirm?: string;
};

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

type RiskArchiveOptions = JsonOptions & {
  write?: boolean;
  confirm?: string;
};

type RiskLinkControlsOptions = JsonOptions & {
  controlId?: string[];
  replace?: boolean;
  write?: boolean;
  confirm?: string;
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

type MonitorWriteOptions = JsonOptions & {
  write?: boolean;
  confirm?: string;
};

type MonitorSetEnabledOptions = MonitorWriteOptions & {
  enabled: string;
  disabledReason?: string;
  reviewRemindAt?: string;
};

type MonitorSnoozeOptions = MonitorWriteOptions & {
  until: string;
  reason?: string;
};

type MonitorSetConfigOptions = MonitorWriteOptions & {
  configJson: string;
};

type MonitorAssetIgnoreOptions = MonitorWriteOptions & {
  ignoreAssetId?: string[];
  unignoreAssetId?: string[];
  reason?: string;
};

type ControlFeedbackOptions = TenantOptions & {
  status?: string[];
  limit: string;
  showIds?: boolean;
};

type ControlReviewWriteOptions = TenantOptions & {
  write?: boolean;
  confirm?: string;
};

type AccessReviewMarkEmptyVendorsOptions = JsonOptions & {
  note?: string;
  showIds?: boolean;
  write?: boolean;
  confirm?: string;
};

type EvidenceUploadDescription = {
  fileName: string;
  sizeBytes: number;
  type: "FILE" | "IMAGE";
  contents: Uint8Array;
};

type AccessReviewVendorTarget = {
  id: string;
  status: string | null;
  accountCount: number;
  reviewedAtPresent: boolean;
};

type AccessReviewEmptyVendorSelection = {
  vendorCount: number;
  zeroAccountVendorCount: number;
  alreadyReviewedZeroAccountVendorCount: number;
  skippedWithAccountsCount: number;
  missingIdCount: number;
  targets: AccessReviewVendorTarget[];
};

const DEFAULT_EMPTY_ACCESS_REVIEW_VENDOR_NOTE =
  "No detected account-level access in Oneleet at review time; marked not applicable for access certification.";
const ALLOWED_POLICY_AUDIENCES = new Set(["EVERYONE", "EMPLOYEES", "CONTRACTORS", "GROUPS"]);
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

function normalizeControlFeedbackStatuses(values: string[] | undefined): Set<string> | null {
  const normalized = (values && values.length > 0 ? values : ["NEEDS_CHANGES"]).map((value) => value.trim().toUpperCase()).filter(Boolean);
  if (normalized.some((value) => value === "ALL")) return null;
  return new Set(normalized);
}

function buildPolicyAudiencePatch(opts: PolicySetAudienceOptions): Record<string, unknown> {
  if (opts.audience === undefined) {
    throw codeError("VALIDATION", "--audience is required. Allowed: " + Array.from(ALLOWED_POLICY_AUDIENCES).join(", ") + ".");
  }
  const audience = opts.audience.trim().toUpperCase().replace(/-/g, "_");
  if (!ALLOWED_POLICY_AUDIENCES.has(audience)) {
    throw codeError("VALIDATION", "Invalid --audience value. Allowed: " + Array.from(ALLOWED_POLICY_AUDIENCES).join(", ") + ".");
  }
  const groupIds = (Array.isArray(opts.groupId) ? opts.groupId : []).map((value) => {
    const trimmed = value.trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
      throw codeError("VALIDATION", "--group-id must be a UUID.");
    }
    return trimmed;
  });
  if (audience !== "GROUPS" && groupIds.length > 0) {
    throw codeError("VALIDATION", "--group-id is only valid with --audience GROUPS.");
  }
  // For GROUPS we send the (possibly empty) group list; an empty list means no one is required to sign.
  // For EVERYONE/EMPLOYEES/CONTRACTORS the server derives membership, so only the audience is sent.
  return audience === "GROUPS" ? { audience, groupIds } : { audience };
}

function sanitizePolicy(value: unknown): Record<string, unknown> {
  const row = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const version = row.currentVersion && typeof row.currentVersion === "object" ? (row.currentVersion as Record<string, unknown>) : {};
  const countOf = (key: string): number | null => (Array.isArray(version[key]) ? (version[key] as unknown[]).length : null);
  return {
    id: row.id,
    name: row.name,
    audience: row.audience,
    reviewerType: row.reviewerType,
    types: Array.isArray(row.types)
      ? row.types.map((type) => {
          const t = type && typeof type === "object" ? (type as Record<string, unknown>) : {};
          return t.name;
        })
      : [],
    currentVersionApplicableMemberCount: countOf("applicableTenantMembers"),
    currentVersionDirectSignatureCount: countOf("directSignatures") ?? countOf("applicableSignatures"),
    updatedAt: row.updatedAt,
  };
}

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

function buildMonitorEnabledPatch(opts: MonitorSetEnabledOptions): Record<string, unknown> {
  const enabled = parseBooleanOption(opts.enabled, "--enabled");
  const patch: Record<string, unknown> = { enabled };
  if (opts.disabledReason !== undefined) setString(patch, "disabledReason", opts.disabledReason);
  if (opts.reviewRemindAt !== undefined) patch.reviewRemindAt = parseIsoTimestamp(opts.reviewRemindAt, "--review-remind-at");
  return patch;
}

function buildMonitorSnoozePatch(opts: MonitorSnoozeOptions): Record<string, unknown> {
  const patch: Record<string, unknown> = {
    snoozedUntil: parseIsoTimestamp(opts.until, "--until"),
    reason: opts.reason?.trim() || "",
  };
  return patch;
}

function buildMonitorAssetIgnorePatch(opts: MonitorAssetIgnoreOptions): Record<string, unknown> {
  const assetsToIgnore = uniqueUuidList(opts.ignoreAssetId || [], "ignore asset id");
  const assetsToUnignore = uniqueUuidList(opts.unignoreAssetId || [], "unignore asset id");
  if (assetsToIgnore.length === 0 && assetsToUnignore.length === 0) {
    throw codeError("VALIDATION", "Provide at least one --ignore-asset-id or --unignore-asset-id.");
  }
  return {
    assetsToIgnore,
    assetsToUnignore,
    reasonToIgnore: opts.reason?.trim() || "",
  };
}

function accessReviewMarkReviewedNote(opts: AccessReviewMarkEmptyVendorsOptions): string {
  const note = (opts.note ?? DEFAULT_EMPTY_ACCESS_REVIEW_VENDOR_NOTE).trim();
  if (!note) throw codeError("VALIDATION", "--note cannot be empty.");
  return note;
}

function buildAccessReviewMarkReviewedForm(note: string): FormData {
  const form = new FormData();
  form.append("note", note);
  return form;
}

function selectEmptyAccessReviewVendors(value: unknown): AccessReviewEmptyVendorSelection {
  const vendors = accessReviewVendorsOf(value);
  const selection: AccessReviewEmptyVendorSelection = {
    vendorCount: vendors.length,
    zeroAccountVendorCount: 0,
    alreadyReviewedZeroAccountVendorCount: 0,
    skippedWithAccountsCount: 0,
    missingIdCount: 0,
    targets: [],
  };

  for (const vendor of vendors) {
    const accountCount = accessReviewVendorAccountCount(vendor);
    const reviewed = isAccessReviewVendorReviewed(vendor);
    if (accountCount > 0) {
      selection.skippedWithAccountsCount += 1;
      continue;
    }

    selection.zeroAccountVendorCount += 1;
    if (reviewed) {
      selection.alreadyReviewedZeroAccountVendorCount += 1;
      continue;
    }

    const id = typeof vendor.id === "string" ? vendor.id : "";
    if (!id) {
      selection.missingIdCount += 1;
      continue;
    }

    selection.targets.push({
      id,
      status: typeof vendor.status === "string" ? vendor.status : null,
      accountCount,
      reviewedAtPresent: Boolean(vendor.reviewedAt),
    });
  }

  return selection;
}

function accessReviewVendorsOf(value: unknown): Record<string, unknown>[] {
  const row = unwrapData(value);
  return Array.isArray(row.vendors) ? row.vendors.filter((vendor): vendor is Record<string, unknown> => Boolean(vendor && typeof vendor === "object")) : [];
}

function accessReviewVendorAccountCount(value: Record<string, unknown>): number {
  return Array.isArray(value.accessReviewAccounts) ? value.accessReviewAccounts.length : 0;
}

function isAccessReviewVendorReviewed(value: Record<string, unknown>): boolean {
  return value.status === "REVIEWED" || Boolean(value.reviewedAt);
}

function describeEmptyAccessReviewVendorSelection(
  accessReview: unknown,
  accessReviewId: string,
  selection: AccessReviewEmptyVendorSelection,
  note: string,
  showIds: boolean,
): Record<string, unknown> {
  const row = unwrapData(accessReview);
  return {
    accessReviewId,
    accessReviewStatus: row.status || null,
    hasTitle: Boolean(row.title),
    note,
    summary: {
      vendorCount: selection.vendorCount,
      zeroAccountVendorCount: selection.zeroAccountVendorCount,
      alreadyReviewedZeroAccountVendorCount: selection.alreadyReviewedZeroAccountVendorCount,
      skippedWithAccountsCount: selection.skippedWithAccountsCount,
      missingIdCount: selection.missingIdCount,
      targetCount: selection.targets.length,
    },
    targets: selection.targets.map((target, index) => summarizeAccessReviewVendorTarget(target, index, showIds)),
  };
}

function summarizeAccessReviewVendorTarget(target: AccessReviewVendorTarget, index: number, showIds: boolean): Record<string, unknown> {
  const row: Record<string, unknown> = {
    ref: `access-review-vendor-${String(index + 1).padStart(3, "0")}`,
    hasId: Boolean(target.id),
    status: target.status,
    accountCount: target.accountCount,
    reviewedAtPresent: target.reviewedAtPresent,
  };
  if (showIds) row.id = target.id;
  return row;
}

function parseJsonObjectOption(value: string | undefined, label: string): Record<string, unknown> {
  if (!value?.trim()) throw codeError("VALIDATION", `${label} is required.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error: any) {
    throw codeError("VALIDATION", `${label} must be valid JSON: ${error?.message || "parse failed"}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw codeError("VALIDATION", `${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function parseBooleanOption(value: string | undefined, label: string): boolean {
  const normalized = (value || "").trim().toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  throw codeError("VALIDATION", `${label} must be true or false.`);
}

function parseIsoTimestamp(value: string | undefined, label: string): string {
  const candidate = (value || "").trim();
  if (!candidate) throw codeError("VALIDATION", `${label} cannot be empty.`);
  const date = new Date(candidate);
  if (Number.isNaN(date.getTime())) throw codeError("VALIDATION", `${label} must be an ISO-like date/time string.`);
  return candidate;
}

function uniqueUuidList(ids: string[], label: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    const normalized = requireUuid(id, label);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function requireWriteConfirmation(confirm: string | undefined, expected: string, label = "monitor id"): void {
  if (confirm !== expected) throw codeError("VALIDATION", `--write requires --confirm to exactly match the ${label}.`);
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
  const row = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
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
    archivedAt: row.archivedAt || null,
    controls: Array.isArray(row.controls)
      ? row.controls.map((control) => {
          const c = control && typeof control === "object" ? (control as Record<string, unknown>) : {};
          const controlType = c.controlType && typeof c.controlType === "object" ? (c.controlType as Record<string, unknown>) : {};
          return {
            id: c.id || null,
            title: c.title || controlType.title || null,
            status: c.status || null,
          };
        })
      : [],
    updatedAt: row.updatedAt,
  };
}

function controlIdsOfRisk(row: Record<string, unknown>): string[] {
  if (!Array.isArray(row.controls)) return [];
  return row.controls
    .map((control) => {
      const c = control && typeof control === "object" ? (control as Record<string, unknown>) : {};
      return typeof c.id === "string" ? c.id : "";
    })
    .filter(Boolean);
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
  if (isUuid(candidate)) return candidate;
  throw codeError("VALIDATION", `Invalid ${label}. Expected a UUID.`);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim());
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

function sanitizeMonitor(value: unknown): Record<string, unknown> {
  const row = unwrapData(value);
  const monitorType = row.monitorType && typeof row.monitorType === "object" ? (row.monitorType as Record<string, unknown>) : {};
  const stats = row.stats && typeof row.stats === "object" ? (row.stats as Record<string, unknown>) : {};
  const assets = stats.assets && typeof stats.assets === "object" ? (stats.assets as Record<string, unknown>) : {};
  const latestRun = row.latestRun && typeof row.latestRun === "object" ? (row.latestRun as Record<string, unknown>) : {};
  const currentState = row.currentState && typeof row.currentState === "object" ? (row.currentState as Record<string, unknown>) : {};
  return {
    id: row.id,
    status: row.status || null,
    isEnabled: row.isEnabled ?? row.enabled ?? null,
    statusChangedAt: row.statusChangedAt || null,
    monitorType: monitorType.name || null,
    controlTitles: Array.isArray(row.controlSummaries)
      ? row.controlSummaries
          .map((control) => (control && typeof control === "object" ? (control as Record<string, unknown>).title : null))
          .filter(Boolean)
      : [],
    assets: {
      count: assets.count ?? null,
      failingCount: assets.failingCount ?? null,
      passingCount: assets.passingCount ?? null,
      percentPassing: assets.percentPassing ?? null,
    },
    latestRunStatus: latestRun.status || null,
    latestRunAt: latestRun.createdAt || latestRun.updatedAt || null,
    currentStateStatus: currentState.status || null,
    updatedAt: row.updatedAt || null,
  };
}

type MonitorRow = Record<string, any>;

type ResolvedMonitor = {
  id: string;
  ref: string;
  row: MonitorRow;
  index: number;
};

type ResolvedControl = {
  id: string;
  ref: string | null;
  row: Record<string, any> | null;
  index: number | null;
};

type MonitorWaitResult = {
  completed: boolean;
  reason: "not-requested" | "completed" | "timeout";
  row: MonitorRow | null;
  index: number | null;
};

const MONITOR_REF_PATTERN = /^monitor-(\d+)$/;
const CONTROL_REF_PATTERN = /^control-(\d+)$/;
const ACTIVE_RUN_STATUSES = new Set(["PENDING", "RUNNING", "IN_PROGRESS", "RETRYING", "UNQUERIED"]);

function rowsFromMonitorList(raw: unknown): MonitorRow[] {
  if (!raw || typeof raw !== "object" || !Array.isArray((raw as any).rows)) {
    throw codeError("CHECK_FAILED", "Unexpected monitor list response shape.");
  }
  return (raw as any).rows;
}

function resolveMonitorForRefresh(selector: string, rows: MonitorRow[]): ResolvedMonitor {
  const match = MONITOR_REF_PATTERN.exec(selector);
  if (!match) {
    throw codeError("VALIDATION", "Monitor must be a local ref like monitor-014 from `oneleet monitors list`.");
  }

  const index = Number(match[1]) - 1;
  if (!Number.isSafeInteger(index) || index < 0 || index >= rows.length) {
    throw codeError("NOT_FOUND", "No monitor exists for that local ref in the current monitor list.");
  }
  return monitorAt(rows, index);
}

async function resolveMonitorSelector(
  client: ReturnType<typeof clientFor>,
  tenantId: string,
  selector: string,
): Promise<ResolvedMonitor> {
  if (isUuid(selector)) {
    return { id: selector, ref: "", row: {}, index: -1 };
  }
  return resolveMonitorForRefresh(selector, rowsFromMonitorList(await client.listMonitors(tenantId)));
}

async function resolveControlSelector(
  client: ReturnType<typeof clientFor>,
  tenantId: string,
  selector: string,
): Promise<ResolvedControl> {
  if (isUuid(selector)) {
    return { id: selector, ref: null, row: null, index: null };
  }
  const match = CONTROL_REF_PATTERN.exec(selector);
  if (!match) {
    throw codeError("VALIDATION", "Control must be a UUID or local ref like control-044 from `oneleet controls list`.");
  }
  const rows = rowsOf(await client.listControls(tenantId)) as Record<string, any>[];
  const index = Number(match[1]) - 1;
  if (!Number.isSafeInteger(index) || index < 0 || index >= rows.length) {
    throw codeError("NOT_FOUND", "No control exists for that local ref in the current control list.");
  }
  const row = rows[index];
  if (!row || typeof row.id !== "string" || !row.id.trim()) {
    throw codeError("CHECK_FAILED", "Control row is missing an upstream id required for this command.");
  }
  return { id: row.id, ref: controlRefForIndex(index), row, index };
}

function monitorAt(rows: MonitorRow[], index: number): ResolvedMonitor {
  const row = rows[index];
  if (!row || typeof row.id !== "string" || !row.id.trim()) {
    throw codeError("CHECK_FAILED", "Monitor row is missing an upstream id required for rerun.");
  }
  return {
    id: row.id,
    ref: refForIndex(index),
    row,
    index,
  };
}

function refForIndex(index: number): string {
  return `monitor-${String(index + 1).padStart(3, "0")}`;
}

function controlRefForIndex(index: number): string {
  return `control-${String(index + 1).padStart(3, "0")}`;
}

function parseWaitSeconds(value: string): number {
  if (!/^\d+$/.test(value)) throw codeError("VALIDATION", "--wait must be an integer number of seconds.");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 300) {
    throw codeError("VALIDATION", "--wait must be between 0 and 300 seconds.");
  }
  return parsed;
}

function monitorRunKey(row: MonitorRow): string {
  const latestRun = row?.latestRun && typeof row.latestRun === "object" ? row.latestRun : {};
  return [latestRun.id, latestRun.createdAt, latestRun.updatedAt, latestRun.status].filter(Boolean).join(":");
}

async function readMonitorAfterRefresh(
  client: ReturnType<typeof clientFor>,
  tenantId: string,
  monitorId: string,
  beforeRunKey: string,
  waitSeconds: number,
): Promise<MonitorWaitResult> {
  if (waitSeconds === 0) {
    const current = await findMonitorById(client, tenantId, monitorId);
    return { completed: false, reason: "not-requested", row: current?.row || null, index: current?.index ?? null };
  }

  const deadline = Date.now() + waitSeconds * 1000;
  let latest: { row: MonitorRow; index: number } | null = null;

  while (Date.now() <= deadline) {
    latest = await findMonitorById(client, tenantId, monitorId);
    if (latest) {
      const status = String(latest.row?.latestRun?.status || "");
      const runChanged = Boolean(monitorRunKey(latest.row)) && monitorRunKey(latest.row) !== beforeRunKey;
      if (runChanged && !ACTIVE_RUN_STATUSES.has(status)) {
        return { completed: true, reason: "completed", row: latest.row, index: latest.index };
      }
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(2000, remainingMs));
  }

  return { completed: false, reason: "timeout", row: latest?.row || null, index: latest?.index ?? null };
}

async function findMonitorById(
  client: ReturnType<typeof clientFor>,
  tenantId: string,
  monitorId: string,
): Promise<{ row: MonitorRow; index: number } | null> {
  const rows = rowsFromMonitorList(await client.listMonitors(tenantId));
  const index = rows.findIndex((row) => row?.id === monitorId);
  return index >= 0 ? { row: rows[index], index } : null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
