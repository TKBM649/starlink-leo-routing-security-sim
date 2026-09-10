starlink/
├── PLAN.md
├── .gitignore
├── REORGANIZE_LOG.md         
├── configs/
│   └── experiments/
│       ├── e2_jamming.yaml
│       └── e3_blackhole.yaml
├── data/
│   ├── lattice/               lattice_result.pkl, lattice_summary.json
│   ├── snapshots/             
│   ├── tle/                   starlink.tle, filtered_records.pkl, filter_report.json
│   └── topology/              events_{43,53,70,97_5}deg.txt, topology_results.pkl, topology_summary.json
├── docs/                      
├── results/
│   ├── aggregated/            simulation_summary.json
│   ├── figures/               attack_seed42_44.csv, e2_analysis_seed42_44.png, ...
│   ├── raw/                   aggregated_blackhole_e3_seed4{2,3,4}.json, routing_tables.pkl, ...
│   └── viz/                   starlink_3d_final{,_v1,_v2}.html
├── scripts/
│   ├── analyze_e2.py
│   ├── analyze_e3_results.py
│   ├── build_lattice.py
│   ├── build_topology.py
│   ├── build_topology_from_tle.py
│   ├── import_tle.py
│   ├── run_e2_jamming_experiment.py
│   ├── run_e3_blackhole_experiment.py
│   ├── run_simulation.py
│   └── visualize_3d_optimized.py
├── starlink_sim/
│   ├── __init__.py
│   ├── analytics/             
│   ├── io/                    
│   ├── net/
│   │   ├── attack.py
│   │   ├── attack_jamming.py
│   │   ├── routing_dv.py
│   │   ├── simulator.py
│   │   ├── simulator_blackhole.py
│   │   └── simulator_jamming.py
│   ├── orbit/
│   │   ├── lattice.py
│   │   ├── shells.py
│   │   └── tle.py
│   └── topology/
│       └── isl.py
├── tests/
│   ├── test_dv.py
│   └── test_tle.py
└── tools/
    ├── check_imports.py
    └── check_shell.py
