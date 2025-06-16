#[allow(warnings)]
mod bindings;

use bindings::Guest;
use klave;
use serde_json::Value;

pub mod database;

struct Component;
impl Guest for Component {

    fn register_routes(){
        klave::router::add_user_transaction(&String::from("sql_create"));
        klave::router::add_user_transaction(&String::from("sql_delete"));
        klave::router::add_user_query(&String::from("sql_list"));
        klave::router::add_user_query(&String::from("sql_query"));
        klave::router::add_user_query(&String::from("sql_execute"));

        klave::router::add_user_query(&String::from("document_create"));
        klave::router::add_user_query(&String::from("document_delete"));
        klave::router::add_user_query(&String::from("document_list"));
    }

    //endpoints to test Postgres client management
    fn sql_create(cmd: String) {
        let input: database::CreateInput = match serde_json::from_str(&cmd) {
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
            &input.host,
            &input.dbname,
            &input.user,
            &input.password
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

        match client.query_and_format::<Vec<Vec<Value>>>(&input.input) {
            Ok(result) => {
                let _ = klave::notifier::send_json(&result);
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Query failed: {}", err));
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

}

bindings::export!(Component with_types_in bindings);
