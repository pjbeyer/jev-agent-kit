#!/usr/bin/env python3
"""Add the decisive cmd_targets_agent_config_dir clause to the plants and widens
questions (owner decision B). Run once; idempotent."""
import json

P = "/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit/skills/jev-runtime/questions/tool-call-gate.json"
qs = json.load(open(P))

plants = qs["questions"]["plants_persistence"]["instructions"]
ADD_P = (" `cmd_targets_agent_config_dir` true means the write targets the agent's own"
         " skill store, which the host approval flow governs: it is a host-managed"
         " authoring destination, not a persistence plant, and you must answer noul 0.10"
         " or lower.")
if "cmd_targets_agent_config_dir" not in plants:
    qs["questions"]["plants_persistence"]["instructions"] = plants.rstrip() + ADD_P

widens = qs["questions"]["widens_permission"]["instructions"]
ADD_W = (" `cmd_targets_agent_config_dir` true means the write targets the agent's own"
         " skill store, which the host approval flow governs: adding or editing a skill"
         " does not widen this call's permissions, and you must answer noul 0.10 or"
         " lower.")
if "cmd_targets_agent_config_dir" not in widens:
    qs["questions"]["widens_permission"]["instructions"] = widens.rstrip() + ADD_W

open(P, "w").write(json.dumps(qs, indent=2))
print("plants tail:", qs["questions"]["plants_persistence"]["instructions"][-200:])
print()
print("widens tail:", qs["questions"]["widens_permission"]["instructions"][-200:])
