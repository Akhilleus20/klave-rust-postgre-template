#[allow(warnings)]
mod bindings;

use bindings::Guest;
use klave;
use serde_json::Value;

pub mod database;
pub mod crypto;
pub mod utils;

struct Component;
impl Guest for Component {

    fn register_routes(){
        klave::router::add_user_transaction(&String::from("db_setup"));
        klave::router::add_user_transaction(&String::from("sql_delete"));
        klave::router::add_user_query(&String::from("sql_list"));
        klave::router::add_user_query(&String::from("sql_query"));
        klave::router::add_user_query(&String::from("sql_execute"));

        klave::router::add_user_query(&String::from("read_encrypted_table"));
        klave::router::add_user_query(&String::from("execute_table_encryption"));
    }

    //endpoints to test Postgres client management
    fn db_setup(cmd: String) {
        let input: database::DBInputDetails = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };

        let mut clients = match database::Clients::load() {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load clients: {}", err));
                return;
            }
        };

        match clients.add(
            input.clone(),
        ) {
            Ok(database_id) => {
                klave::notifier::send_string(&database_id);
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to add database client: {}", err));
                return;
            }
        };
    }

    fn sql_delete(cmd: String) {
        let input: database::DeleteInput = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };

        let mut clients = match database::Clients::load() {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load clients: {}", err));
                return;
            }
        };
        if clients.delete(&input.database_id).is_err() {
            klave::notifier::send_string("Failed to add database client.");
            return;
        }
    }

    fn sql_list(_: String) {
        match database::Clients::load() {
            Ok(clients) => {
                let list_clients = match clients.list() {
                    Ok(list) => list,
                    Err(err) => {
                        klave::notifier::send_string(&format!("Failed to list clients: {}", err));
                        return;
                    }
                };
                let _ = klave::notifier::send_json(&list_clients);
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load clients: {}", err));
            }
        }
    }

    fn sql_query(cmd: String) {
        let input: database::QueryClient = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };

        let mut client: database::Client = match database::Client::load(input.database_id) {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load client: {}", err));
                return;
            }
        };

        let _ = match client.connect() {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to client: {}", err));
                return;
            }
        };

        match client.query::<Vec<Vec<Value>>>(&input.input) {
            Ok(result) => {
                let _ = klave::notifier::send_json(&result);
                return;
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Query failed: {}", err));
                return;
            }
        }
    }

    fn sql_execute(cmd: String) {
        let input: database::QueryClient = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };

        let mut client: database::Client = match database::Client::load(input.database_id) {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load client: {}", err));
                return;
            }
        };

        let _ = match client.connect() {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to client: {}", err));
                return;
            }
        };

        match client.execute(&input.input) {
            Ok(result) => {
                let _ = klave::notifier::send_json(&result);
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Query failed: {}", err));
            }
        }
    }

    fn execute_table_encryption(cmd: String) {
        let db_table: database::DBTable = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };

        let mut client: database::Client = match database::Client::load(db_table.database_id.clone()) {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load client: {}", err));
                return;
            }
        };
        let _ = match client.connect() {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to client: {}", err));
                return;
            }
        };
        let _ = match client.encrypt_columns(db_table) {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to encrypt columns: {}", err));
                return;
            }
        };
    }

    fn read_encrypted_table(cmd: String) {
        let input: database::ReadEncryptedTableInput = match serde_json::from_str(&cmd) {
            Ok(input) => input,
            Err(err) => {
                klave::notifier::send_string(&format!("Invalid input: {}", err));
                return;
            }
        };
        let mut client: database::Client = match database::Client::load(input.database_id.clone()) {
            Ok(c) => c,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load client: {}", err));
                return;
            }
        };
        let _ = match client.connect() {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to client: {}", err));
                return;
            }
        };
        let encrypted_query = match client.build_encrypted_query(input) {
            Ok(enc_query) => enc_query,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to create encrypted query: {}", err));
                return;
            }
        };

        let _ = match client.query::<Vec<Vec<Value>>>(&encrypted_query) {
            Ok(res) => {
                let _ = klave::notifier::send_json(&res);
                return;
            }
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to use encrypted query: {}", err));
                return;
            }
        };
    }
}

bindings::export!(Component with_types_in bindings);
