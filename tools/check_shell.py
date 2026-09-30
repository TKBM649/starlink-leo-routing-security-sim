import pickle

with open('data/topology/topology_results.pkl', 'rb') as f:
    topo_data = pickle.load(f)
    print("Top-level keys:", list(topo_data.keys()))
    
    # 检查 '53°' 壳层的内部结构
    shell_53 = topo_data['53°']
    print("\nType of shell_53:", type(shell_53))
    if isinstance(shell_53, dict):
        print("Keys in shell_53:", list(shell_53.keys()))
        # 如果有 'edges' 或 'edge_sets'，查看其长度
        if 'edges' in shell_53:
            print("edges length:", len(shell_53['edges']))
        if 'num_nodes' in shell_53:
            print("num_nodes:", shell_53['num_nodes'])
    elif isinstance(shell_53, list):
        print("First element type:", type(shell_53[0]))
        # 如果是边集列表
        if isinstance(shell_53[0], set):
            print("It appears to be a list of edge sets.")
            print("Number of epochs:", len(shell_53))