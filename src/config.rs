use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub looking_glasses: Vec<LookingGlassConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LookingGlassConfig {
    pub name: String,
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub prompt_suffix: Option<String>,
    pub template: Option<String>,
    pub cmd_template: Option<String>,
    pub pager_cmd: Option<String>,
}

impl LookingGlassConfig {
    /// Resolves the actual BGP query command template, prioritizing manual override,
    /// then template-specific defaults, falling back to Cisco IPv4.
    pub fn resolve_cmd_template(&self) -> String {
        if let Some(ref cmd) = self.cmd_template {
            return cmd.clone();
        }
        match self.template.as_deref() {
            Some("cisco_ipv6") => "show bgp ipv6 unicast {prefix}".to_string(),
            Some("juniper") | Some("juniper_ipv4") | Some("juniper_ipv6") => {
                "show route protocol bgp {prefix}".to_string()
            }
            Some("cisco_ipv4") | Some("cisco") | _ => "show ip bgp {prefix}".to_string(),
        }
    }

    /// Resolves the actual terminal pagination command, prioritizing manual override,
    /// then template-specific defaults, falling back to Cisco terminal length 0.
    pub fn resolve_pager_cmd(&self) -> Option<String> {
        if let Some(ref pager) = self.pager_cmd {
            return Some(pager.clone());
        }
        match self.template.as_deref() {
            Some("juniper") | Some("juniper_ipv4") | Some("juniper_ipv6") => {
                Some("set cli screen-length 0".to_string())
            }
            Some("cisco_ipv4") | Some("cisco") | Some("cisco_ipv6") => {
                Some("terminal length 0".to_string())
            }
            _ => None,
        }
    }
}
