//! Network configuration for test/demo nodes

use std::collections::HashMap;

/// Supported network environments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Local regtest network (docker-compose.yml)
    Regtest,
    /// Mutinynet public signet (docker-compose-mutinynet.yml)
    Mutinynet,
}

impl Network {
    /// Parse network from string
    pub fn from_str(s: &str) -> Option<Network> {
        match s.to_lowercase().as_str() {
            "regtest" => Some(Network::Regtest),
            "mutinynet" | "signet" => Some(Network::Mutinynet),
            _ => None,
        }
    }

    /// Get subnet base for this network
    pub fn subnet_base(&self) -> &'static str {
        match self {
            Network::Regtest => "172.20.0",
            Network::Mutinynet => "172.21.0",
        }
    }

    /// Get list of valid network names for help text
    pub fn valid_names() -> &'static str {
        "regtest, mutinynet"
    }
}

/// Configuration for a single node in the test network
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Node name
    pub name: String,
    /// API port
    pub api_port: u16,
    /// P2P port
    pub p2p_port: u16,
    /// IP address
    pub ip: String,
    /// Node role
    pub role: String,
}

/// Network configuration helper
pub struct NetworkConfig;

impl NetworkConfig {
    /// Get all available node configurations for a specific network
    pub fn nodes_for_network(network: Network) -> HashMap<String, NodeConfig> {
        let subnet = network.subnet_base();
        let mut nodes = HashMap::new();

        // Production nodes (alice through frank)
        let production_nodes = [
            ("alice", "Alice", 3011, 9735, 20),
            ("bob", "Bob", 3012, 9736, 21),
            ("charlie", "Charlie", 3013, 9737, 22),
            ("diana", "Diana", 3014, 9738, 23),
            ("eve", "Eve", 3015, 9739, 24),
            ("frank", "Frank", 3016, 9740, 25),
        ];

        // Development nodes
        let dev_nodes = [("grace", "Grace", 3017, 9741, 30)];

        for (id, name, api_port, p2p_port, last_octet) in production_nodes {
            nodes.insert(
                id.to_string(),
                NodeConfig {
                    name: name.to_string(),
                    api_port,
                    p2p_port,
                    ip: format!("{}.{}", subnet, last_octet),
                    role: "production".to_string(),
                },
            );
        }

        for (id, name, api_port, p2p_port, last_octet) in dev_nodes {
            nodes.insert(
                id.to_string(),
                NodeConfig {
                    name: name.to_string(),
                    api_port,
                    p2p_port,
                    ip: format!("{}.{}", subnet, last_octet),
                    role: "development".to_string(),
                },
            );
        }

        nodes
    }

    /// Get all available node configurations (defaults to regtest)
    pub fn all_nodes() -> HashMap<String, NodeConfig> {
        Self::nodes_for_network(Network::Regtest)
    }

    /// Get production nodes only (alice through frank)
    pub fn production_nodes() -> HashMap<String, NodeConfig> {
        Self::all_nodes()
            .into_iter()
            .filter(|(_, config)| config.role == "production")
            .collect()
    }

    /// Get development nodes only (grace, etc.)
    pub fn development_nodes() -> HashMap<String, NodeConfig> {
        Self::all_nodes()
            .into_iter()
            .filter(|(_, config)| config.role == "development")
            .collect()
    }

    /// Get default node set (production nodes)
    pub fn default_nodes() -> Vec<String> {
        vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ]
    }

    /// Get default node set including development nodes
    pub fn default_with_dev_nodes() -> Vec<String> {
        let mut nodes = Self::default_nodes();
        nodes.extend(Self::development_nodes().keys().cloned());
        nodes
    }

    /// Get all node IDs as a sorted vector
    pub fn all_node_ids() -> Vec<String> {
        let mut ids: Vec<String> = Self::all_nodes().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get all node names for help text
    pub fn all_node_names_string() -> String {
        Self::all_node_ids().join(", ")
    }

    /// Get a specific node configuration
    pub fn get_node(node_id: &str) -> Option<NodeConfig> {
        Self::all_nodes().get(node_id).cloned()
    }

    /// Check if a node ID exists
    pub fn is_valid_node(node_id: &str) -> bool {
        Self::all_nodes().contains_key(node_id)
    }

    /// Get nodes for status tool (simplified format for backwards compatibility)
    pub fn status_node_configs() -> Vec<(&'static str, &'static str, u16)> {
        vec![
            ("alice", "Alice", 3011),
            ("bob", "Bob", 3012),
            ("charlie", "Charlie", 3013),
            ("diana", "Diana", 3014),
            ("eve", "Eve", 3015),
            ("frank", "Frank", 3016),
            ("grace", "Grace", 3017),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_nodes_includes_grace() {
        let nodes = NetworkConfig::all_nodes();
        assert!(nodes.contains_key("grace"));
        assert_eq!(nodes["grace"].name, "Grace");
        assert_eq!(nodes["grace"].api_port, 3017);
    }

    #[test]
    fn test_production_nodes_excludes_grace() {
        let nodes = NetworkConfig::production_nodes();
        assert!(!nodes.contains_key("grace"));
        assert_eq!(nodes.len(), 6); // alice through frank
    }

    #[test]
    fn test_development_nodes_includes_grace() {
        let nodes = NetworkConfig::development_nodes();
        assert!(nodes.contains_key("grace"));
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn test_default_with_dev_includes_grace() {
        let nodes = NetworkConfig::default_with_dev_nodes();
        assert!(nodes.contains(&"grace".to_string()));
        assert_eq!(nodes.len(), 4); // 3 production (alice, bob, charlie) + 1 dev (grace)
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(Network::from_str("regtest"), Some(Network::Regtest));
        assert_eq!(Network::from_str("REGTEST"), Some(Network::Regtest));
        assert_eq!(Network::from_str("mutinynet"), Some(Network::Mutinynet));
        assert_eq!(Network::from_str("signet"), Some(Network::Mutinynet));
        assert_eq!(Network::from_str("invalid"), None);
    }

    #[test]
    fn test_network_subnet_base() {
        assert_eq!(Network::Regtest.subnet_base(), "172.20.0");
        assert_eq!(Network::Mutinynet.subnet_base(), "172.21.0");
    }

    #[test]
    fn test_nodes_for_network_regtest() {
        let nodes = NetworkConfig::nodes_for_network(Network::Regtest);
        assert_eq!(nodes["alice"].ip, "172.20.0.20");
        assert_eq!(nodes["bob"].ip, "172.20.0.21");
    }

    #[test]
    fn test_nodes_for_network_mutinynet() {
        let nodes = NetworkConfig::nodes_for_network(Network::Mutinynet);
        assert_eq!(nodes["alice"].ip, "172.21.0.20");
        assert_eq!(nodes["bob"].ip, "172.21.0.21");
    }
}
