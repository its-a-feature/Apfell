import json as js
import pprint

file = open("full_attack.json", "r")
output = open("small_attack.json", "w")
attack = js.load(file)
attack_list = []
for obj in attack["objects"]:
    if obj["type"] == "attack-pattern":
        t_num = "Not Found"  # just an error case
        for ext_ref in obj["external_references"]:
            if "external_id" in ext_ref and ext_ref["source_name"] == "mitre-attack":
                t_num = ext_ref["external_id"]
                name = obj["name"]
                if "x_mitre_platforms" in obj:  # "x_mitre_platform" is now not always present
                    os = " ".join(obj["x_mitre_platforms"])
                else:
                    os = ""
                tactics = [
                    x["phase_name"]
                    for x in (obj["kill_chain_phases"] if "kill_chain_phases" in obj else []) # Neither is "kill_chain_phases"
                    if x["kill_chain_name"] == "mitre-attack"
                ]
                tactics = " ".join(tactics)
                # tactic = obj['kill_chain_phases'][0]['phase_name']
                attack_list.append(
                    {"t_num": t_num, "name": name, "os": os, "tactic": tactics}
                )
full_output = {"techniques": attack_list}
output.write(js.dumps(full_output))
