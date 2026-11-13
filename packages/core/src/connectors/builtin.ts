/** Registers the connectors that ship with Vigil. Imported for its side effect by the package entry point and the DSL. */
import { listConnectors, registerConnector } from "./registry.js";
import { gcpConnectorDefinition } from "./gcp.js";
import { awsConnectorDefinition } from "./aws.js";
import { azureConnectorDefinition } from "./azure.js";
import { datadogConnectorDefinition } from "./datadog.js";
import { newRelicConnectorDefinition } from "./newrelic.js";

const BUILTIN = [gcpConnectorDefinition, awsConnectorDefinition, azureConnectorDefinition, datadogConnectorDefinition, newRelicConnectorDefinition];

if (listConnectors().length === 0) for (const d of BUILTIN) registerConnector(d);

export const BUILTIN_CONNECTOR_IDS = BUILTIN.map((d) => d.id);
