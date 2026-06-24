# GNN-DQN-MAFS Agent Models

These are the **10 trained GNN-DQN agents** that form the Multi-Agent Feature Selection (MAFS) system.

## Role in the Framework

The GNN-DQN-MAFS system is the **feature selection phase** of the framework:

1. **Input**: 430 raw XSS features extracted from web traffic
2. **Process**: 10 cooperating GNN-DQN agents evaluate and select the most relevant features using reinforcement learning
3. **Output**: 226 optimal features selected (out of 430)
4. **Result**: `../xss_classifier.joblib` was trained on these 226 features

## Files

| File | Description |
|------|-------------|
| `gcn_late_agent_0.keras` | GNN-DQN Agent 0 — trained feature selector |
| `gcn_late_agent_1.keras` | GNN-DQN Agent 1 — trained feature selector |
| `gcn_late_agent_2.keras` | GNN-DQN Agent 2 — trained feature selector |
| `gcn_late_agent_3.keras` | GNN-DQN Agent 3 — trained feature selector |
| `gcn_late_agent_4.keras` | GNN-DQN Agent 4 — trained feature selector |
| `gcn_late_agent_5.keras` | GNN-DQN Agent 5 — trained feature selector |
| `gcn_late_agent_6.keras` | GNN-DQN Agent 6 — trained feature selector |
| `gcn_late_agent_7.keras` | GNN-DQN Agent 7 — trained feature selector |
| `gcn_late_agent_8.keras` | GNN-DQN Agent 8 — trained feature selector |
| `gcn_late_agent_9.keras` | GNN-DQN Agent 9 — trained feature selector |

## Architecture

- **GNN** (Graph Neural Network): Models relationships between features as a graph
- **DQN** (Deep Q-Network): Reinforcement learning to decide which features to keep
- **Multi-Agent**: 10 agents cooperate to cover all 430 features, each managing a subset

## Thesis

**Cybersecurity framework for Detection and Prevention of Cross-Site Scripting Attacks
Using Hybrid Deep Learning Techniques**

- Student: Ali Nafea Yousif
- Supervised By: Prof. Dr. Ziyad Tariq Mustafa Al-Ta'i
