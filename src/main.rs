
// YAML files as iptables configuration sources

// Rust Core
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::exit;

// Crate.io
extern crate clap;
extern crate yaml_rust;

use clap::{Arg, App, AppSettings};
use yaml_rust::{Yaml, YamlLoader};

fn main() {

    let app = App::new("iptables-compose")
        .version("1.1.0")
        .settings(&[
            AppSettings::UnifiedHelpMessage,
            AppSettings::GlobalVersion,
            AppSettings::ArgRequiredElseHelp
        ])
        .about("\nYAML files as iptables configuration sources")
        .arg(Arg::with_name("CONFIG")
             .multiple(false)
             .help("yaml file as iptables configuration source")
             .conflicts_with("license")
             .index(1))
        .arg(Arg::with_name("RESET")
             .short("r")
             .long("reset")
             .help("reset iptables rules\n")
             .requires("CONFIG"))
        .args_from_usage("-l --license 'Prints License'");

    let matches = app.get_matches();

    if let Some(ref f_path) = matches.value_of("CONFIG") {
        // Reset rules if "reset" argument is present
        if matches.is_present("RESET") {
            reset_rules();
        }
        read_yaml(f_path);
    }

    if matches.is_present("license") {
        print_license();
    }

}

fn print_license() {
    let s:String = "
The MIT License (MIT)

Copyright (c) 2015 Samuel <sam@infinitely.io>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
".to_string();
    println!("{}", s);
}

fn read_yaml(f_path: &str) {

    // Create a path for yaml configuration file
    let path = Path::new(&f_path);
    let display = path.display();

    // Open file
    let mut file = match File::open(&path) {
        Err(_)   => {
            println!("Failed to open file \"{}\"", display);
            exit(1);
        },
        Ok(file) => file,
    };

    // Create buffer string and read content
    let mut buffer_str = String::new();
    match file.read_to_string(&mut buffer_str) {
        Err(_)  => {
            println!("Failed to read file \"{}\"", display);
            exit(1);
        },
        Ok(str) => str,
    };

    // Parse yaml file
    let yaml = match YamlLoader::load_from_str(&buffer_str) {
        Err(_)  => {
            println!("Failed to parse yaml data: \"{}\"", display);
            exit(1);
        },
        Ok(yaml) => yaml,
    };

    // Check if yaml file has no data, exits program if no data
    if yaml.is_empty() {
        println!("\"{}\" has no configuration(s)", display);
        exit(1);
    };

    // Validate configuration template format
    match yaml[0].as_hash() {
        Some(doc) => doc,
        None => {
            println!("Configuration template format is invalid: {}", display);
            exit(1);
        }
    };

    // Parse configuration from YAML configuration file
    parse_yaml(&yaml[0]);

}

fn parse_yaml(doc: &Yaml) {
    // Read all rules from yaml
    match doc {
        // Parse if template data is a hash object
        &Yaml::Hash(ref h) => {
            for (k, v) in h {
                match k.as_str().unwrap() {
                    // Parse `filter` rules
                    "filter" | "FILTER" => parse_filter(v),
                    // Parse custom section
                    _ => parse_section(v)
                }
            }
        },
        _ => {
            println!("Configuration template format is invalid");
            exit(1);
        }
    }
}

// fn opposite_direction(direction: &str) -> &str {
//     match direction {
//         "INPUT" => {
//             return "OUTPUT";
//         },
//         "OUTPUT" => {
//             return "INPUT";
//         },
//         _ => {
//             return &direction;
//         }
//     }
// }

fn reset_rules() {
    let mut s:String = "iptables -F".to_string();
    s.push_str("\niptables -X");
    s.push_str("\niptables -t nat -F");
    s.push_str("\niptables -t nat -X");
    s.push_str("\niptables -t mangle -F");
    s.push_str("\niptables -t mangle -X");
    println!("{}", s);
}

fn parse_section(doc: &Yaml) {
    match doc {
        &Yaml::Hash(ref h) => {
            for (k, v) in h {
                let k = k.as_str().unwrap();
                match k {
                    "raw" | "RAW" => parse_raw(v),
                    "matches" | "MATCHES" => parse_match(v),
                    "ports" | "PORTS" => parse_ports(v),
                    _ => {
                        println!("Rules \"{}\" is not available", k);
                        exit(1);
                    }
                }
            }
        },
        _ => {
            println!("Configuration template format is invalid");
            exit(1);
        }
    }
}

fn parse_raw(doc: &Yaml) {
    match doc {
        &Yaml::Array(ref v) => {
            for x in v {
                parse_raw_item(x);
            }
        },
        _ => {
            println!("Configuration \"matches\" format is invalid");
            exit(1);
        }
    }
}

fn parse_raw_item(doc: &Yaml) {
    match doc {
        &Yaml::String(_) => {
            println!("{}", &doc.as_str().unwrap());
        },
        // &Yaml::Hash(_) => {
        //     println!(doc.as_str());
        // },
        _ => {
            println!("Configuration \"raw\" item format is invalid");
            exit(1);
        }
    }
}

fn parse_match(doc: &Yaml) {
    match doc {
        &Yaml::Array(ref v) => {
            for x in v {
                parse_match_item(x);
            }
        },
        _ => {
            println!("Configuration \"matches\" format is invalid");
            exit(1);
        }
    }
}

fn parse_match_item(doc: &Yaml) {
    match doc {
        &Yaml::Hash(_) => {
            if doc["match"].is_badvalue() {
                println!("match is not defined");
                exit(1);
            }

            let mut cmd:String = "iptables".to_string();
            let direction = doc["type"].as_str().unwrap_or("input");
            match direction {
                "input" | "output" | "forward" | "INPUT" | "OUTPUT" | "FORWARD" => {
                    cmd.push_str(" -I ");
                    cmd.push_str(&direction.to_ascii_uppercase());
                },
                _ => {
                    println!("Direction value is invalid");
                    exit(1);
                }
            }

            cmd.push_str(" -m ");
            let match_type = doc["match"].as_str().unwrap();
            cmd.push_str(&match_type);
            match doc["state"] {
                Yaml::Array(ref v) => {
                    cmd.push_str(" --state ");
                    let mut y: i32 = 0;
                    for x in v {
                        if y > 0 {
                            cmd.push_str(",");
                        }
                        cmd.push_str(x.as_str().unwrap());
                        y += 1;
                    }
                },
                _ => {}
            }
            match doc["ctstate"] {
                Yaml::Array(ref v) => {
                    cmd.push_str(" --ctstate ");
                    let mut y: i32 = 0;
                    for x in v {
                        if y > 0 {
                            cmd.push_str(",");
                        }
                        cmd.push_str(x.as_str().unwrap());
                        y += 1;
                    }
                },
                _ => {}
            }

            let allow = doc["allow"].as_bool().unwrap_or(true);
            cmd.push_str(" -j ");
            match allow {
                true => {
                    cmd.push_str("ACCEPT");
                },
                _ => {
                    cmd.push_str("DROP");
                }
            }
            println!("{}", cmd);
        },
        _ => {
            println!("Configuration \"states\" item format is invalid");
            exit(1);
        }
    }
}

fn parse_ports(doc: &Yaml) {
    match doc {
        &Yaml::Array(ref v) => {
            for x in v {
                parse_port_item(x);
            }
        },
        _ => {
            println!("Configuration \"ports\" format is invalid");
            exit(1);
        }
    }
}

fn parse_port_item(doc: &Yaml) {
    match doc {
        &Yaml::Hash(_) => {
            if doc["port"].is_badvalue() && doc["ports"].is_badvalue() {
                println!("Port and ports are not defined");
                exit(1);
            }
            let mut port_str:String = "".to_string();
            if !doc["port"].is_badvalue() {
                let port = doc["port"].as_i64();
                match port {
                    Some(port) if port > -1 => (),
                    _ => {
                        if port.unwrap() <= -1 {
                            println!("Port has to be greater or equals to 0");
                        } else {
                            println!("Port is not invalid");
                        }
                        exit(1);
                    }
                }
                port_str.push_str(" --dport ");
                port_str.push_str(&port.unwrap().to_string());
            }
            else if !doc["ports"].is_badvalue() {
                match doc["ports"] {
                    Yaml::Array(ref v) => {
                        port_str.push_str(" -m multiport --dports ");
                        let mut y: i32 = 0;
                        for x in v {
                            match x {
                                &Yaml::String(ref str) => {
                                    if y > 0 {
                                        port_str.push_str(",");
                                    }
                                    port_str.push_str(str);
                                    y += 1;
                                }
                                &Yaml::Integer(ref n) => {
                                    if y > 0 {
                                        port_str.push_str(",");
                                    }
                                    port_str.push_str(&n.to_string());
                                    y += 1;
                                }
                                _ => {
                                    println!("Invalid ports, must be string of port range type 'port1:port2' or integer");
                                    exit(1);
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
            let mut cmd:String = "iptables".to_string();
            let mut cmd_reverse:String = "iptables".to_string();
            if ! doc["forward"].is_badvalue() {
                cmd.push_str(" -t nat -A PREROUTING");
            } else {
                let direction = doc["type"].as_str().unwrap_or("input");
                match direction {
                    "input" | "output" | "forward" | "INPUT" | "OUTPUT" | "FORWARD" => {
                        cmd.push_str(" -A ");
                        cmd.push_str(&direction.to_ascii_uppercase());
                        cmd_reverse.push_str(" -I ");
                        cmd_reverse.push_str(&direction.to_ascii_uppercase());
                        // cmd_reverse.push_str(&opposite_direction(&direction.to_ascii_uppercase()));
                    },
                    _ => {
                        println!("Direction value is invalid");
                        exit(1);
                    }
                }
            }
            match doc["src"] {
                Yaml::Array(ref v) => {
                    cmd.push_str(" -s ");
                    cmd_reverse.push_str(" -d ");
                    let mut y: i32 = 0;
                    for x in v {
                        if y > 0 {
                            cmd.push_str(",");
                            cmd_reverse.push_str(",");
                        }
                        cmd.push_str(x.as_str().unwrap_or("0.0.0.0/0"));
                        cmd_reverse.push_str(x.as_str().unwrap_or("0.0.0.0/0"));
                        y += 1;
                    }
                },
                _ => {}
            }
            match doc["dst"] {
                Yaml::Array(ref v) => {
                    cmd.push_str(" -d ");
                    cmd_reverse.push_str(" -s ");
                    let mut y: i32 = 0;
                    for x in v {
                        if y > 0 {
                            cmd.push_str(",");
                            cmd_reverse.push_str(",");
                        }
                        cmd.push_str(x.as_str().unwrap_or("0.0.0.0/0"));
                        cmd_reverse.push_str(x.as_str().unwrap_or("0.0.0.0/0"));
                        y += 1;
                    }
                },
                _ => {}
            }
            let protocol = doc["protocol"].as_str().unwrap_or("tcp");
            match protocol {
                "tcp" | "TCP" => {
                    cmd.push_str(" -p ");
                    cmd.push_str(protocol);
                    // cmd.push_str(" -m state ");
                    // cmd.push_str(" --state NEW ");
                    cmd_reverse.push_str(" -p ");
                    cmd_reverse.push_str(protocol);
                },
                "udp" | "UDP" => {
                    cmd.push_str(" -p ");
                    cmd.push_str(protocol);
                    cmd_reverse.push_str(" -p ");
                    cmd_reverse.push_str(protocol);

                    // cmd.push_str(" -m ");
                    // cmd.push_str(protocol);
                },
                _ => {
                    println!("Protocol value is invalid");
                    exit(1);
                }
            }
            match doc["state"] {
                Yaml::Array(ref v) => {
                    cmd.push_str(" -m state --state ");
                    let mut y: i32 = 0;
                    for x in v {
                        if y > 0 {
                            cmd.push_str(",");
                        }
                        cmd.push_str(x.as_str().unwrap());
                        y += 1;
                    }
                },
                _ => {}
            }

            cmd.push_str(&port_str);
            // cmd_reverse.push_str(" --sport ");
            // cmd_reverse.push_str(&port.unwrap().to_string());
            if ! doc["forward"].is_badvalue() {
                let forward = doc["forward"].as_i64();
                match forward {
                    Some(forward) if forward > -1 => (),
                    _ => {
                        if forward.unwrap() <= -1 {
                            println!("forward port has to be greater or equals to 0");
                        } else {
                            println!("forward port is not invalid");
                        }
                        exit(1);
                    }
                }
                cmd.push_str(" -j REDIRECT --to-port ");
                cmd.push_str(&forward.unwrap().to_string());
            } else {
                let allow = doc["allow"].as_bool().unwrap_or(true);
                cmd.push_str(" -j ");
                cmd_reverse.push_str(" -j ");
                match allow {
                    true => {
                        cmd.push_str("ACCEPT");
                        cmd_reverse.push_str("ACCEPT");
                    },
                    _ => {
                        cmd.push_str("DROP");
                        cmd_reverse.push_str("DROP");
                        cmd_reverse.clear();
                    }
                }
            }
            println!("{}", cmd);
            // if cmd_reverse.len() > 0 {
            //     println!("{}", cmd_reverse);
            // }
        },
        _ => {
            println!("Configuration \"ports\" item format is invalid");
            exit(1);
        }
    }
}

fn parse_filter(doc: &Yaml) {
    // Check if filter section exists
    match doc {
        &Yaml::Hash(ref h) => {
            for (k, v) in h {
                let k = k.as_str().unwrap();
                let v = v.as_str().unwrap();
                match k {
                    "input" | "output" | "forward" | "INPUT" | "OUTPUT" | "FORWARD" => {
                        match v {
                            "drop" | "reject" | "accept" | "DROP" | "REJECT" | "ACCEPT" => println!("iptables -P {} {}", k.to_ascii_uppercase(), v.to_ascii_uppercase()),
                            _ => {
                                println!("Rules \"{}\" only accept options of \"drop\",\"reject\" or \"accept\"", k);
                                exit(1);
                            }
                        }
                    },
                    _ => println!("iptables -P {}", k.to_ascii_uppercase())
                }
            }
        },
        _ => {
            println!("Configuration template format is invalid");
            exit(1);
        }
    }
}
