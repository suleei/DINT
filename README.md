# Artifact for paper "DINT: Distributed Data Plane Verification Using In-band Network Telemetry"

* The data plane part of DINT is located in the folder "data plane"
* The control plane part of DINT is located in the folder "control plane"
* Network topology is located in the folder "topology"
* Our implementation of EPVerifier is located in the folder "EPVerifier-Implementation"

* EPVerifier implementation is based on Flash[https://github.com/snlab/flash]
* DINT's data plane procedure is written in P4[https://github.com/p4lang] and run on Mininet[https://github.com/mininet/mininet] with BMv2 switch[https://github.com/p4lang/behavioral-model].
* DINT's control plane procedure uses P4Runtime[https://github.com/p4lang/p4runtime] for interaction with the data plane and Rudd[https://github.com/dalzilio/rudd] for BDD operations.
