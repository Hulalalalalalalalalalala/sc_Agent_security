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
export declare function waitForLoopbackSecret(
  secretFile?: string,
  maxWaitMs?: number
): Promise<string>;
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
  discoverPeers(opts?: {
    skill?: string | null;
    trustDomain?: string | null;
    onlyHealthy?: boolean;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
  requestPeerConsent(opts: {
    requestId: string;
    requiredSkill?: string | null;
    delegateSpiffeId?: string | null;
    trustDomain?: string | null;
    tools: string[];
    ownerOidcToken: string;
    numericBounds?: Record<string, number> | null;
    allowedTargets?: string[] | null;
    paramWhitelist?: Record<string, string[]> | null;
    maxCalls?: number;
    handshakeHopSegment?: string;
    consentHopSegment?: string | null;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
  callMCPTool(
    requestId: string,
    targetUrl: string | null,
    toolName: string,
    toolArgs?: Record<string, unknown>,
    opts?: {
      requiredSkill?: string | null;
      targetSpiffeId?: string | null;
      targetTrustDomain?: string | null;
      idempotencyKey?: string | null;
      redactDigestJws?: boolean;
      timeoutSec?: number;
    }
  ): Promise<{ status: number; body: Record<string, unknown> }>;
  callMCPToolCoAuth(opts: {
    requestId: string;
    consentHandle: string;
    toolName: string;
    toolArgs?: Record<string, unknown>;
    requiredSkill?: string | null;
    targetSpiffeId?: string | null;
    targetTrustDomain?: string | null;
    idempotencyKey?: string | null;
    redactDigestJws?: boolean;
    timeoutSec?: number;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
  callPeerCoAuth(opts: {
    requestId: string;
    consentHandle: string;
    payload?: Record<string, unknown>;
    permissions?: PermissionLatticeJSON | null;
    requiredSkill?: string | null;
    delegateSpiffeId?: string | null;
    trustDomain?: string | null;
    hopSegment?: string;
    taskPath?: string;
    idempotencyKey?: string | null;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
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
