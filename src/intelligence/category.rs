use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ThreatCategory {
    Common = 1,
    Cloud = 2,
    Ssh = 3,
    Vcs = 4,
    Ide = 5,
    Wordpress = 6,
    Php = 7,
    Laravel = 8,
    Actuator = 9,
    Webmail = 10,
    Backups = 11,
}

impl ThreatCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Common => "common",
            Self::Cloud => "cloud",
            Self::Ssh => "ssh",
            Self::Vcs => "vcs",
            Self::Ide => "ide",
            Self::Wordpress => "wordpress",
            Self::Php => "php",
            Self::Laravel => "laravel",
            Self::Actuator => "actuator",
            Self::Webmail => "webmail",
            Self::Backups => "backups",
        }
    }

    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Common),
            2 => Some(Self::Cloud),
            3 => Some(Self::Ssh),
            4 => Some(Self::Vcs),
            5 => Some(Self::Ide),
            6 => Some(Self::Wordpress),
            7 => Some(Self::Php),
            8 => Some(Self::Laravel),
            9 => Some(Self::Actuator),
            10 => Some(Self::Webmail),
            11 => Some(Self::Backups),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
