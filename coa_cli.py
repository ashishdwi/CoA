from securicad import enterprise
import configparser
import re
import json
import zipfile
import shutil
import os
from attackg import AttackGraph, merge_attack_graphs

temp_inf = 1.7976931348623157e+308

################# your input required


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('coa.ini')

    # Create an authenticated enterprise client
    print("Log in to Enterprise...", end="")
    client = enterprise.client(
        base_url=config["enterprise-client"]["url"],
        username=config["enterprise-client"]["username"],
        password=config["enterprise-client"]["password"],
        organization=config["enterprise-client"]["org"] if config["enterprise-client"]["org"] else None,
        cacert=config["enterprise-client"]["cacert"] if config["enterprise-client"]["cacert"] else False
    )
    print("done")

    # Get the project where the model will be added
    #project = client.projects.get_project_by_name("test")  ################# old
    project = client.projects.get_project_by_name("CoA")  #################
    print("Project pid  -- ", project.pid)

    # Get the model info for the target model from the project
    models = enterprise.models.Models(client).list_models(project)
    for model in models:
     print(model.mid)

    models = enterprise.models.Models(client)
    #modelinfo = models.get_model_by_mid(project, "238548676164277")  ################# old
    #modelinfo = models.get_model_by_mid(project, "226155404398940")  #################
    #modelinfo = models.get_model_by_mid(project, "333288092317090")
    modelinfo = models.get_model_by_mid(project, "243886861364858")
    # TODO get the model from simulation id

    print("model name  -- ", modelinfo.name)

    # download the model
    '''datapath = 'data-models'
    if not os.path.exists(datapath):
        os.makedirs(datapath)
    model_path = "data-models/temp.sCAD"
    scad_dump = modelinfo.get_scad()
    #print(scad_dump)
    print("model downloaded")
    f1 = open(model_path, "wb")
    f1.write(scad_dump)
    f1.close()

    # unzip the model
    model_dir_path = model_path[:model_path.rindex('/')]
    model_file_name = model_path[model_path.rindex('/')+1:model_path.rindex('.')]
    unzip_dir = "scad_dir"
    unzip_dir_path = "{}/{}".format(model_dir_path, unzip_dir)
    with zipfile.ZipFile(model_path, 'r') as zip_ref:
        zip_ref.extractall(unzip_dir_path)
    eom_path = "{}/{}.eom".format(unzip_dir_path, model_file_name)
    print("model unzipped in  -- ", unzip_dir_path)

    # delete the downloaded model file
    # os.remove(model_path)
    # print("downloaded model deleted")

    # zip the model
    shutil.make_archive(base_name='{}/tempTemp'.format(model_dir_path), format='zip', root_dir=unzip_dir_path)
    zipped_path = '{}/tempTemp.zip'.format(model_dir_path)
    sCAD_path = '{}/tempTemp.sCAD'.format(model_dir_path)
    os.rename(zipped_path, sCAD_path)
    print("model zipped")


    # upload the model
    f1 = open(sCAD_path, "rb")
    modelinfo = models.upload_scad_model(project, "tempTemp.sCAD", f1)
    f1.close()
    print("model uploaded")

    # delete the .sCAD file and model file
    os.remove(sCAD_path)
    # delete all the files in scad_dir
    shutil.rmtree(unzip_dir_path)
    print("model related files deleted")'''



    # scenario
    scenarios = enterprise.scenarios.Scenarios(client)

    # cleaning old scenarios
    print("scenario cleaning process started ...")
    scen_arios = scenarios.list_scenarios(project)
    for scen_ario in scen_arios:
        scen_ario.delete()
    print("cleaning done")

    # create scenario
    scenario = scenarios.create_scenario(project, modelinfo, "test")

    print("scenario created")

    # create simulation
    simulations = enterprise.simulations.Simulations(client)
    simulation = simulations.create_simulation(scenario)
    print("simulation created")




    # get ttc values
    simres = simulation.get_results()
    with open("Simulation_Result.json", "w") as outfile:
        json.dump(simres, outfile)
    ttcs = {}
    for risks_i in simres["results"]["risks"]:
        ttcs[risks_i["attackstep_id"]] = [round(float(risks_i["ttc5"]), 3), round(float(risks_i["ttc50"]), 3), round(float(risks_i["ttc95"]), 3)]
        print("TTC values for ", risks_i["attackstep_id"], "is", ttcs[risks_i["attackstep_id"]])
    steps_of_interest = ["{}".format(risks_i["attackstep_id"]) for risks_i in simres["results"]["risks"]]
    print("Steps of interest are: ", steps_of_interest)

    # get all critical paths
    # cri_path = simulation.get_critical_paths(None)

    # Must "cheat" here and call a raw API to obtain full language meta.
    # The SDK method client.metadata.get_metadata() will not provide everything needed.
    print("Obtaining full language metadata", end="")
    lang_meta = client._get("metadata")

    attack_paths = []

    # get selected critical paths - where ttc5 is less than infinity
    for risks_i in simres["results"]["risks"]:
        if round(float(risks_i["ttc5"]), 3) == temp_inf:
            continue
        cri_path = simulation.get_critical_paths([risks_i["attackstep_id"]])
        print("critical path fetched")
        with open("cp.json", "w") as outfile:
            json.dump(cri_path, outfile)
        ag = AttackGraph(cri_path, risks_i["attackstep_id"], lang_meta)
        print("critical path converted to a graph")
        attack_paths.append(ag)

    # # code for debugging


    graph = merge_attack_graphs(attack_paths)


    crit_metric = 'f'
    graph.find_critical_attack_step(crit_metric)

    best_def_info = graph.find_best_defense()
    print(best_def_info)
    #TODO enable the defense in securicad model

    #exit()

    raw_tunings = []
    #for d in defences:
        # "(<num>) " in name must be trimmed away

        #asset_name = re.sub(r'^\([0-9]+\) ', '', d["name"])
        #attackstep_name = d["attackstep"]
    raw_tunings.append(
        {
            "type": "probability",
            "op": "apply",
            "filter": {"object_name": best_def_info["name"], "defense": best_def_info["attackstep"], "tags": {}},
            "probability": 1.0
        }
    )

    coa_sim = client.simulations.create_simulation(scenario,
                                                   name="With tuning",
                                                   raw_tunings=raw_tunings
                                                   )

    # get ttc values
    simres1 = coa_sim.get_results()
    with open("Simulation_Result1.json", "w") as outfile1:
        json.dump(simres1, outfile1)
    ttcs = {}
    for risks_i in simres1["results"]["risks"]:
        ttcs[risks_i["attackstep_id"]] = [round(float(risks_i["ttc5"]), 3), round(float(risks_i["ttc50"]), 3), round(float(risks_i["ttc95"]), 3)]
        print("TTC values for ", risks_i["attackstep_id"], "is", ttcs[risks_i["attackstep_id"]])
    steps_of_interest = ["{}".format(risks_i["attackstep_id"]) for risks_i in simres1["results"]["risks"]]

    attack_paths = []

    # get selected critical paths - where ttc5 is less than infinity
    for risks_i in simres1["results"]["risks"]:
        if round(float(risks_i["ttc5"]), 3) == temp_inf:
            continue
        cri_path1 = coa_sim.get_critical_paths([risks_i["attackstep_id"]])
        print("critical path fetched")
        with open("cp1.json", "w") as outfile1:
            json.dump(cri_path1, outfile1)
        ag = AttackGraph(cri_path1, risks_i["attackstep_id"], lang_meta)
        print("critical path converted to a graph")
        attack_paths.append(ag)


