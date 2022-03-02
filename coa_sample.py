# Copyright 2021 Foreseeti AB <https://foreseeti.com>
from securicad import enterprise
import configparser
import re


#
# Get the project and target model for optimizing defenses
def initial_simulation(client: enterprise.Client, project: str, model: str) -> \
        tuple[enterprise.Scenario, enterprise.ModelInfo, enterprise.Simulation, dict]:
    project = client.projects.get_project_by_name(project)
    model = client.models.get_model_by_name(project, model)
    scenario = client.scenarios.create_scenario(project, model, "CoA lab")
    simulation = client.simulations.get_simulation_by_name(
        scenario, name="Initial simulation"
    )
    # Poll for results and return them when simulation is done
    result = simulation.get_results()

    return scenario, model, simulation, result


def coa_eligible_defense(cp_node: dict, lang_meta: dict) -> bool:

    # If it is a defense at all...
    if not cp_node["isDefense"]:
        return False

    # .. it must not be suppressed and have a cost
    classdefs = lang_meta["assets"][cp_node["class"]]["defenses"]
    defense_info = next((d for d in classdefs if d["name"] == cp_node["attackstep"]), False)
    # Fixme: Think about how to handle missing defense here. TSNH, but still...
    if "suppress" not in defense_info["tags"] and "cost" in defense_info["metaInfo"]:
        return True

    return False


def main():
    config = configparser.ConfigParser()
    config.read('coa.ini')

    # Create an authenticated enterprise client
    print("Log in to Enterprise...", end="")
    client = enterprise.client(
        base_url=config["enterprise-client"]["url"],
        username=config["enterprise-client"]["username"],
        password=config["enterprise-client"]["password"],
        organization=config["enterprise-client"]["org"],
        cacert=config["enterprise-client"]["cacert"] if config["enterprise-client"]["cacert"] else False
    )
    print("done")

    print("Running initial simulation...", end="")
    (scenario, model, sim, res) = initial_simulation(client,
                                                     config["project"]["project_name"],
                                                     config["project"]["model_name"])
    print("done")
    print("TTC results for initial simulation:")
    for r in res["results"]["risks"]:
        print(f"{r['object_name']}({r['object_id']}).{r['attackstep']}: ttc5={r['ttc5']}, ttc50={r['ttc50']}, ttc95={r['ttc95']}")

    cp = sim.get_critical_paths()

    # Must "cheat" here and call a raw API to obtain full language meta.
    # The SDK method client.metadata.get_metadata() will not provide everything needed.
    print("Obtaining full language metadata and adding fake cost...", end="")
    lang_meta = client._get("metadata")

    #
    # Remove me! I am fake code to add cost as a JSON dict to SoftwareVulnerability.Remove
    # {first_use: <integer>, subsequent_use: <integer>}
    svds = lang_meta["assets"]["SoftwareVulnerability"]["defenses"]
    svr = next((d for d in svds if d["name"] == "Remove"), False)
    svr["metaInfo"]["cost"] = '{"first_use":50, "subsequent_use":100}'
    print("done")

    #
    # Find set of disabled defenses from the CPs and filter out the defenses
    # that have cost information.
    # These are the available defenses for the CoA algorithm

    # Iterate over all high value assets and collect all nodes with isDefense = True
    # and where the defense has a cost setting from the language
    defs = []
    for hva in cp:
        defs.extend([node for node in cp[hva]["nodes"] if coa_eligible_defense(node, lang_meta)])

    print("CoA-eligible defenses from initial simulation:")
    for d in defs:
        print(d)

    #
    # Run the CoA algorithm based on the available and eligible defenses.
    # Here is only a sample to apply all defenses as raw_tunings in a
    # simulation in the same Scenario as the initial simulation.
    #
    # Working with raw tunings should be beneficial as we will otherwise
    # "pollute" the project with numerous persisted tunings.

    # Critical Path name of objects is prefixed with "(id) ". Must remove this
    # as tunings require the actual name.
    # Fixme for PE: How to work with tunings when object have the
    #               same names?

    print("Applying all eligible defenses in new simulation...", end="")
    raw_tunings = []
    for d in defs:
        # "(<num>) " in name must be trimmed away
        asset_name = re.sub(r'^\([0-9]+\) ', '', d["name"])
        attackstep_name = d["attackstep"]
        raw_tunings.append(
            {
                "type": "probability",
                "op": "apply",
                "filter": {"object_name": asset_name, "defense": attackstep_name, "tags": {}},
                "probability": 1.0
             }
        )

    coa_sim = client.simulations.create_simulation(scenario,
                                                   name="With tuning",
                                                   raw_tunings=raw_tunings
                                                   )
    coa_sample_res = coa_sim.get_results()
    print("done")
    print("TTC results for single-sample CoA defenses:")
    for r in coa_sample_res["results"]["risks"]:
        print(f"{r['object_name']}({r['object_id']}).{r['attackstep']}: ttc5={r['ttc5']}, ttc50={r['ttc50']}, ttc95={r['ttc95']}")


if __name__ == "__main__":
    main()
