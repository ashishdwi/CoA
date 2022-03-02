# Introduction:
The Course of Action (CoA) generator component operates on a model of an ICT infrastructure produced by the ADG component. The CoA generator component searches for “inactive defences” in the model and suggests to activate a set of them that have been identified as the most effective given a predefined budget.

# Requirements and installation:
The CoA generator component requires a machine (dedicated hardware or virtual) with at least 8GB RAM and 20GB of storage, and currently supports the following operating systems: Windows and Ubuntu Server 18.04/20.04. Execution of the CoA generator component requires user creden-tials.

# Language Support:
The CoA generator component is independent of the modelling language ADG is using, as long as it is defined in the Meta Attack Language. However, defence step implementation costs need to be defined separately per model (or language). In SOCCRATES we use the language named coreLang for which we have assigned some default costs for a subset of all defences in the language.

# Procedures: 
The CoA handles the problem at hand in the following way: given an attack graph, gen-erated from a model of an ICT infrastructure including knowledge of possible defence steps that could be implemented, the CoA generator suggests a set of defence steps the implementation of which increases TTC of specified attack steps, while respecting some constraints. We consider three elementary constraints relevant to implementation of security measures:
1)	limitations on available resources (e.g., fixed budget for operating costs for securing the system),
2)	order dependencies, specifying that some measures can be implemented only in a specific order (e.g., to run an antivirus scan, one needs to install an antivirus component beforehand),
3)	mutual exclusivity between the measures (e.g., if we have two accounts for a service we might for business reasons not be allowed to disable both sim-ultaneously).

# Attack Simulation
An attack graph describes possible behaviour of the attacker and defender in the modelled infra-structure. The attacks, that is, ways in which the attacker can reach their target steps from initial position while respecting the AND and OR requirements of particular steps, correspond to sub-graphs of the graph. While these subgraphs are not necessarily paths in the standard meaning of the word, we will call them attack paths.
