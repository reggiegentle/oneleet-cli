import { DEFAULT_API_BASE_URL, DEFAULT_APP_BASE_URL, type OneleetConfig, stripTrailingSlash } from "./config.js";

export class OneleetApiError extends Error {
  status: number;
  data?: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = "OneleetApiError";
    this.status = status;
    this.data = data;
  }
}

export type RequestQuery = Record<string, string | number | boolean | undefined>;
export type RequestBody = Record<string, unknown>;
export type RequestPayload = RequestBody | FormData;

export class OneleetApiClient {
  private cookie: string;
  private tenantId: string;
  private appBaseUrl: string;
  private apiBaseUrl: string;
  private userAgent: string;

  constructor({
    config,
    userAgent = "oneleet-cli/0.0.0",
  }: {
    config: OneleetConfig;
    userAgent?: string;
  }) {
    this.cookie = config.oneleetAppCookie || "";
    this.tenantId = config.tenantId || "";
    this.appBaseUrl = stripTrailingSlash(config.appBaseUrl || DEFAULT_APP_BASE_URL);
    this.apiBaseUrl = stripTrailingSlash(config.apiBaseUrl || DEFAULT_API_BASE_URL);
    this.userAgent = userAgent;
    assertSafeApiBaseUrl(this.apiBaseUrl, Boolean(config.allowUnsafeApiBaseUrl));
  }

  get configuredTenantId(): string {
    return this.tenantId;
  }

  async getCurrentUser(): Promise<Record<string, unknown>> {
    return this.request("/api/v1/users/current");
  }

  async getMemberships(): Promise<Record<string, unknown>> {
    return this.request("/api/v1/users/current/memberships");
  }

  async getTenant(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}`);
  }

  async getDashboard(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/dashboard`);
  }

  async listMonitors(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/monitors`);
  }

  async listControls(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/controls/program`);
  }

  async listMembers(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/members`);
  }

  async listVendors(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/vendors`);
  }

  async listEvidence(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/evidence`);
  }

  async getEvidence(evidenceId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/evidence/${requireId(evidenceId, "evidence id")}`);
  }

  async createEvidence(tenantId: string, body: FormData): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/evidence`, undefined, {
      method: "POST",
      body,
      bodyType: "form",
    });
  }

  async linkEvidenceToControl(evidenceId: string, body: RequestBody): Promise<unknown> {
    return this.request(`/api/v1/evidence/${requireId(evidenceId, "evidence id")}/link`, undefined, {
      method: "POST",
      body,
    });
  }

  async linkEvidenceToVendor(evidenceId: string, body: RequestBody): Promise<unknown> {
    return this.request(`/api/v1/evidence/${requireId(evidenceId, "evidence id")}/link-to-vendor`, undefined, {
      method: "POST",
      body,
    });
  }

  async listPolicies(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/policies`);
  }

  async listPolicyTypes(): Promise<Record<string, unknown>> {
    return this.request("/api/v1/policy-types");
  }

  async listFrameworks(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/tenant-compliance-frameworks`);
  }

  async listAccessReviews(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/access-reviews`);
  }

  async listDomains(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/domains`);
  }

  async listIntegrations(tenantId = this.tenantId, query: RequestQuery = { includeOneleetManaged: true }): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/integrations`, query);
  }

  async listRiskAssessments(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/risk-assessments`);
  }

  async getRisk(riskId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/risks/${requireId(riskId, "risk id")}`);
  }

  async updateRisk(riskId: string, body: RequestBody): Promise<unknown> {
    return this.request(`/api/v1/risks/${requireId(riskId, "risk id")}`, undefined, {
      method: "PATCH",
      body,
    });
  }

  async archiveRisk(riskId: string): Promise<unknown> {
    return this.request(`/api/v1/risks/${requireId(riskId, "risk id")}/archive`, undefined, {
      method: "POST",
    });
  }

  async unarchiveRisk(riskId: string): Promise<unknown> {
    return this.request(`/api/v1/risks/${requireId(riskId, "risk id")}/unarchive`, undefined, {
      method: "POST",
    });
  }

  async listSecurityTrainingModules(tenantId = this.tenantId, includeDrafts?: boolean): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/security-training-modules`, { includeDrafts });
  }

  async listSecurityTrainingProgress(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/security-training-modules/user-progress`);
  }

  async getTrustConfig(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/trust/config`);
  }

  async listTrustDocuments(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/trust-documents`);
  }

  async listTrustDocumentRequests(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/trust-document-requests`);
  }

  async listTrustFaqs(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/trust-faqs`);
  }

  async listTrustSecurityIssues(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/trust-security-issues`);
  }

  async listReports(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/reports`);
  }

  async getActivePentestRequest(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/pentest-scheduling-requests/active`);
  }

  async getCodeSecurityScan(tenantId = this.tenantId): Promise<Record<string, unknown> | null> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/code-security-scan`);
  }

  async getCodeSecuritySettings(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/code-security-settings`);
  }

  async listGitRepositories(tenantId = this.tenantId): Promise<Record<string, unknown> | unknown[]> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/git-repository`);
  }

  async getAttackSurfaceStats(tenantId = this.tenantId): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/ng-attack-surface/dashboard/stats`);
  }

  async listAttackSurfaceIssues(tenantId = this.tenantId, query: RequestQuery = {}): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/ng-attack-surface/issues`, query);
  }

  async listAttackSurfaceScans(tenantId = this.tenantId, query: RequestQuery = {}): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/tenants/${requireTenantId(tenantId)}/ng-attack-surface/scans`, query);
  }

  async getRaw(path: string, query: RequestQuery = {}): Promise<unknown> {
    const normalized = path.startsWith("/") ? path : `/${path}`;
    if (!normalized.startsWith("/api/v1/")) {
      const error = new OneleetApiError("Only /api/v1/... GET paths are supported by api get", 400) as OneleetApiError & { code: string };
      error.code = "VALIDATION";
      throw error;
    }
    return this.request(normalized, query);
  }

  private buildUrl(path: string, query?: RequestQuery): string {
    const url = new URL(path, this.apiBaseUrl);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === "") continue;
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  private async request(
    path: string,
    query?: RequestQuery,
    options: { method?: "GET" | "PATCH" | "POST" | "DELETE"; body?: RequestPayload; bodyType?: "json" | "form" } = {},
  ): Promise<any> {
    if (!this.cookie) throw new OneleetApiError("No oneleet-app cookie configured", 401);

    const url = this.buildUrl(path, query);
    const method = options.method || "GET";
    const bodyType = options.bodyType || "json";
    const requestBody: BodyInit | undefined =
      options.body === undefined ? undefined : bodyType === "form" ? (options.body as FormData) : JSON.stringify(options.body);
    const response = await fetch(url, {
      method,
      headers: {
        accept: "application/json",
        ...(method !== "GET" && bodyType === "json" ? { "content-type": "application/json" } : {}),
        cookie: `oneleet-app=${this.cookie}`,
        origin: this.appBaseUrl,
        referer: this.tenantId ? `${this.appBaseUrl}/tenants/${this.tenantId}` : this.appBaseUrl,
        "user-agent": this.userAgent,
      },
      body: requestBody,
    });

    const text = await response.text();
    const parsed = text ? tryParseJson(text) : { ok: true as const, value: null };
    const data = parsed.ok ? parsed.value : text;
    if (!response.ok) throw new OneleetApiError(readErrorMessage(response.status, data, text), response.status, data);
    return data;
  }
}

function assertSafeApiBaseUrl(value: string, allowUnsafe: boolean): void {
  if (allowUnsafe) return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw validationError("ONELEET_API_BASE_URL must be a valid URL.");
  }
  if (url.protocol === "https:" && (url.hostname === "api.oneleet.com" || url.hostname.endsWith(".oneleet.com"))) return;
  throw validationError("Refusing to send Oneleet session cookie to a non-Oneleet API host. Set ONELEET_ALLOW_UNSAFE_API_BASE_URL=1 only for synthetic local tests.");
}

function validationError(message: string): OneleetApiError & { code: string } {
  const error = new OneleetApiError(message, 400) as OneleetApiError & { code: string };
  error.code = "VALIDATION";
  return error;
}

function requireTenantId(value: string): string {
  if (value) return value;
  throw new OneleetApiError("No tenant id configured. Run `oneleet auth import-cdp --port 9333` or set ONELEET_TENANT_ID.", 400);
}

function requireId(value: string, label: string): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return value;
  throw validationError(`Invalid ${label}. Expected a UUID.`);
}

function tryParseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

function readErrorMessage(status: number, data: unknown, text: string): string {
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const maybe = (data as Record<string, unknown>).message || (data as Record<string, unknown>).error;
    if (typeof maybe === "string" && maybe.trim()) return maybe;
  }
  return text.trim() ? `Oneleet request failed (${status})` : `Oneleet request failed (${status})`;
}
