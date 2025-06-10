use serde_json;
use serde::{Deserialize, Serialize};

pub(crate) const DATABASE_CLIENT_TABLE: &str = "DatabaseClientTable";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInput {
    pub host: String,
    pub dbname: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteInput {
    pub database_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseIdInput {
    pub database_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHandleClientInput {
    pub database_id: String,
    pub opaque_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clients {
    pub(crate) clients: Vec<String>,
}

impl Clients {
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
        }
    }

    pub fn load() -> Result<Clients, Box<dyn std::error::Error>> {
        match klave::ledger::get_table(DATABASE_CLIENT_TABLE).get("ALL") {
            Ok(v) => {
                let clients: Clients = match serde_json::from_slice(&v) {
                    Ok(w) => w,
                    Err(e) => {
                        klave::notifier::send_string(&format!("ERROR: failed to parse client list: {}", e));
                        return Err(e.into());
                    }
                };
                Ok(clients)
            },
            Err(_e) => {
                let clients: Clients = Clients::new();
                Ok(clients)
            }
        }
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let serialized_clients = match serde_json::to_string(&self) {
            Ok(s) => s,
            Err(e) => {
                klave::notifier::send_string(&format!("ERROR: failed to serialize database Clients: {}", e));
                return Err(e.into());
            }
        };
        klave::ledger::get_table(DATABASE_CLIENT_TABLE).set(&"ALL", &serialized_clients.as_bytes())
    }

    pub fn add(&mut self, host: &str, dbname: &str, user: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let database_id = self.exists(&host, &dbname, &user, &password).to_string();
        if database_id.is_empty() {
            let client = Client::new(
                &host,
                &dbname,
                &user,
                &password
            );
            client.save()?;
            self.clients.push(client.database_id.clone());
            self.save()?;
            Ok(client.database_id)
        } else {
            Ok(database_id)
        }
    }

    pub fn exists(&self, host: &str, dbname: &str, user: &str, password: &str) -> String {
        for database_id in self.clients.iter() {
            if let Ok(client) = Client::load(database_id.to_string()) {
                if client.host == host && client.dbname == dbname && client.user == user && client.password == password {
                    return database_id.to_string();
                }
            }
        }
        String::new()
    }

    pub fn delete(&mut self, database_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(pos) = self.clients.iter().position(|x| x == database_id) {
            self.clients.remove(pos);
            klave::ledger::get_table(DATABASE_CLIENT_TABLE).remove(database_id)?;
            self.save()?;
            Ok(())
        } else {
            Err("Database ID not found".into())
        }
    }

    pub fn list(&self) -> Result<Vec<Client>, Box<dyn std::error::Error>> {
        let mut clients = Vec::new();
        for database_id in &self.clients {
            match Client::load(database_id.to_string()) {
                Ok(client) => clients.push(client),
                Err(e) => {
                    klave::notifier::send_string(&format!("Failed to load client {}: {}", database_id, e));
                }
            }
        }
        Ok(clients)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    database_id: String,
    host: String,
    dbname: String,
    user: String,
    password: String,
    opaque_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryClient {
    pub database_id: String,
    pub input: String,
}


impl Client {

    pub fn new(
        host: &str, dbname: &str,
        user: &str, password: &str
    ) -> Self {
        let database_id = match klave::crypto::random::get_random_bytes(64).map(|x| hex::encode(x)) {
            Ok(id) => id,
            Err(e) => {
                klave::notifier::send_string(&format!("Failed to generate database ID: {}", e));
                String::new()
            }
        };
        Self {
            database_id: database_id,
            host: host.to_string(),
            dbname: dbname.to_string(),
            user: user.to_string(),
            password: password.to_string(),
            opaque_handle: String::new(),
        }
    }

    pub fn get_handle(&self) -> &str {
        &self.opaque_handle
    }

    pub fn load(database_id: String) -> Result<Client, Box<dyn std::error::Error>> {
        match klave::ledger::get_table(DATABASE_CLIENT_TABLE).get(&database_id) {
            Ok(v) => {
                let pgsql_client: Client = match serde_json::from_slice(&v) {
                    Ok(w) => w,
                    Err(e) => {
                        klave::notifier::send_string(&format!("ERROR: failed to deserialize database Client: {}", e));
                        return Err(e.into());
                    }
                };
                Ok(pgsql_client)
            },
            Err(e) => Err(e.into())
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize the Client instance to JSON
        let serialized = serde_json::to_string(self)?;

        // Store the serialized data in the ledger
        klave::ledger::get_table(DATABASE_CLIENT_TABLE).set(&self.database_id, serialized.as_bytes())?;

        Ok(())
    }

    fn connection_string(&self) -> String {
        let mut conn_str = format!("host={} dbname={}", self.host, self.dbname);
        if !self.user.is_empty() {
            conn_str.push_str(&format!(" user={}", self.user));
        }
        if !self.password.is_empty() {
            conn_str.push_str(&format!(" password={}", self.password));
        }
        conn_str
    }

    /// @transaction
    pub fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Construct the PostgreSQL connection URI
        let uri = self.connection_string();

        // Open the PostgreSQL connection
        match klave::sql::connection_open(&uri) {
            Ok(opaque_handle) => {
                klave::notifier::send_string("PostgreSQL connection established successfully.");
                self.opaque_handle = opaque_handle;
                Ok(())
            }
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to PostgreSQL: {}", err));
                Err(err.into())
            }
        }
    }

    pub fn query(&self, query: &str) -> Result<String, Box<dyn std::error::Error>> {
        match klave::sql::query(&self.opaque_handle, query) {
            Ok(result) => Ok(result),
            Err(err) => {
                klave::notifier::send_string(&format!("Query failed: {}", err));
                Err(err.into())
            }
        }
    }
    pub fn execute(&self, query: &str) -> Result<String, Box<dyn std::error::Error>> {
        match klave::sql::execute(&self.opaque_handle, query) {
            Ok(result) => Ok(result),
            Err(err) => {
                klave::notifier::send_string(&format!("Execution failed: {}", err));
                Err(err.into())
            }
        }
    }
}