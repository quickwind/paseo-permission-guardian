import type { PluginServerContext } from "@getpaseo/plugin/server";
import { gateAnnotate, gateReplay } from "../shared/rpc.js";
import type { GateController } from "./gate/gate.js";

/**
 * Registers the gate RPCs. Both await `storeReady` (in-memory history loaded) like the permission
 * hooks do; errors propagate to the RPC caller.
 */
export function registerGateRpcs(
  server: Pick<PluginServerContext, "handle">,
  deps: { gate: Pick<GateController, "replay" | "annotate">; storeReady: Promise<void> },
): void {
  server.handle(gateReplay, async () => {
    await deps.storeReady;
    return deps.gate.replay({ manual: true });
  });
  server.handle(gateAnnotate, async (input) => {
    await deps.storeReady;
    return deps.gate.annotate(input.key, input.annotation);
  });
}
