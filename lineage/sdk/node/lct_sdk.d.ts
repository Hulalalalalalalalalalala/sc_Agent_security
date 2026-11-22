export declare const DEFAULT_SECRET_FILE: string;
export declare const DEFAULT_SIDECAR_OUTBOUND_URL: string;

export interface LCTContext {
  request_id: string;
  task_id: string;
  sub: string;
  lineage_path: string;
  decision: string;
}

export interface PermissionLatticeJSON {
  tools: string[];
  methods: string[];
  max_amount: number | null;
  numeric_bounds: Record<string, number>;
  allowed_scopes: string[] | null;
  allowed_targets: string[] | null;
  param_whitelist: Record<string, string[]>;
  max_calls: number;
}

export declare function loadLoopbackSecret(secretFile?: string): string;
export declare function verifyLoopbackHeader(
  provided: string | undefined,
  expected: string
): boolean;
export declare function extractLCTContext(
  headers: Record<string, string | string[] | undefined>
): LCTContext;
export declare function buildPermissionLattice(opts?: {
  tools?: string[];
  methods?: string[];
  maxAmount?: number | null;
  numericBounds?: Record<string, number>;
  allowedScopes?: string[] | null;
  allowedTargets?: string[] | null;
  paramWhitelist?: Record<string, string[]>;
  maxCalls?: number;
}): PermissionLatticeJSON;

export declare class LCTSidecarClient {
  constructor(loopbackSecret: string, sidecarOutboundUrl?: string);
  callMCPTool(
    requestId: string,
    targetUrl: string,
    toolName: string,
    toolArgs?: Record<string, unknown>
  ): Promise<{ status: number; body: Record<string, unknown> }>;
  delegateAgent(opts: {
    requestId: string;
    payload?: Record<string, unknown>;
    permissions?: PermissionLatticeJSON | null;
    requiredSkill?: string | null;
    delegateSpiffeId?: string | null;
    delegateJkt?: string | null;
    targetUrl?: string | null;
    hopSegment?: string;
    taskPath?: string;
    usePruneAndGraft?: boolean;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
}
