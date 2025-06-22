use std::collections::HashMap;

use hex::encode;
use klave::{crypto::{self, subtle::{derive_key, export_key, save_key, AesGcmParams, CryptoKey, EcKeyGenParams, HkdfDerivParams, KeyDerivationAlgorithm, KeyGenAlgorithm}}, ledger::Table};
use serde_json::{self, Value};
use serde::{Deserialize, Serialize};

use crate::{crypto::{derive_aes_gcm_key, derive_iv, generate_ecc_crypto_key, AES_GCM_IV_SIZE}, utils::{self, get_serde_value_into_bytes, flatten_vec_of_vec_values_to_single_string}};

pub(crate) const DATABASE_CLIENT_TABLE: &str = "DatabaseClientTable";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBInputDetails {
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
pub struct DBTable {
    pub database_id: String,
    pub table: String,
    pub columns: Vec<String>,
    pub primary_key: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadEncryptedTableInput {
    pub database_id: String,
    pub table: String,
    pub encrypted_column: String,
    pub values: Vec<String>
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

    pub fn add(&mut self, db_input_details: DBInputDetails) -> Result<String, Box<dyn std::error::Error>> {
        let database_id = self.exists(&db_input_details).to_string();
        if database_id.is_empty() {
            let mut client = Client::new(
                db_input_details
            );
            client.save()?;
            self.clients.push(client.database_id.clone());
            self.save()?;
            Ok(client.database_id)
        } else {
            Ok(database_id)
        }
    }

    pub fn exists(&self, db_input_details: &DBInputDetails) -> String {
        for database_id in self.clients.iter() {
            if let Ok(client) = Client::load(database_id.to_string()) {
                if client.db_input_details.host == db_input_details.host && client.db_input_details.dbname == db_input_details.dbname
                && client.db_input_details.user == db_input_details.user && client.db_input_details.password == db_input_details.password {
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
    db_input_details: DBInputDetails,
    opaque_handle: String,
    client_id: String,
    master_key_name: Option<String>, // Optional field for master key name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")] // "type" is a reserved keyword in Rust, so we rename it
    pub field_type: u32,
    pub size: u64,
    pub scale: u32,
    pub nullable: bool,
    pub description: Option<String>, // Use Option<String> for nullable fields
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryClient {
    pub database_id: String,
    pub input: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostGreResponse<T> {
    pub fields: Vec<Field>,
    pub resultset: T, // Use Vec<Vec<Value>> for the varying resultset
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionDBDetails {
    pub id: String,
    pub encryption_key_name: String,
}

impl Client {

    pub fn new(
        db_input_details: DBInputDetails
    ) -> Self {
        let database_id = match klave::crypto::random::get_random_bytes(64).map(|x| hex::encode(x)) {
            Ok(id) => id,
            Err(e) => {
                klave::notifier::send_string(&format!("Failed to generate database ID: {}", e));
                String::new()
            }
        };
        let client_id = utils::get_client_id();
        if client_id.is_empty() {
            klave::notifier::send_string("Client ID is empty, cannot create database client.");
        }
        Self {
            database_id: database_id,
            db_input_details: db_input_details,
            opaque_handle: String::new(),
            client_id: client_id,
            master_key_name: None,
        }
    }

    pub fn get_handle(&self) -> &str {
        &self.opaque_handle
    }

    // Loads a Client instance from the ledger using the database ID.
    pub fn load(database_id: String) -> Result<Client, Box<dyn std::error::Error>> {
        match klave::ledger::get_table(DATABASE_CLIENT_TABLE).get(&database_id) {
            Ok(v) => {
                let pgsql_client: Client = match serde_json::from_slice::<Client>(&v) {
                    Ok(w) => {
                        // Check client ID
                        let client_id = utils::get_client_id();
                        if client_id != w.client_id {
                            klave::notifier::send_string("ERROR: Client ID mismatch");
                            return Err("Client ID mismatch".into());
                        }
                        w
                    },
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

    // Saves the master key.
    fn save_master_key(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create master key name
        let master_key_name = hex::encode(klave::crypto::random::get_random_bytes(32)?);
        // Generate master key
        let master_key = match generate_ecc_crypto_key()
        {
            Ok(key) => key,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to generate master key: {}", err));
                return Err(err);
            }
        };
        // Store the master key in the ledger
        let _ = match save_key(&master_key, &master_key_name) {
            Ok(_) => (),
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to save master key: {}", err));
                return Err(err.into());
            }
        };
        self.master_key_name = Some(master_key_name.clone());
        Ok(())
    }

    // Saves the Client instance to the ledger
    pub fn save(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        // Save master key
        self.save_master_key()?;
        // Serialize the Client instance to JSON
        let serialized = serde_json::to_string(self)?;

        // Store the serialized data in the ledger
        klave::ledger::get_table(DATABASE_CLIENT_TABLE).set(&self.database_id, serialized.as_bytes())?;

        Ok(())
    }

    // Constructs the PostgreSQL connection string from the DBInputDetails
    fn connection_string(&self) -> String {
        let mut conn_str = format!("host={} dbname={}", self.db_input_details.host, self.db_input_details.dbname);
        if !self.db_input_details.user.is_empty() {
            conn_str.push_str(&format!(" user={}", self.db_input_details.user));
        }
        if !self.db_input_details.password.is_empty() {
            conn_str.push_str(&format!(" password={}", self.db_input_details.password));
        }
        conn_str
    }

    // Connects to the PostgreSQL database using the connection string
    // and stores the opaque handle for further operations.
    pub fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        // Construct the PostgreSQL connection URI
        let uri = self.connection_string();

        // Open the PostgreSQL connection
        match klave::sql::connection_open(&uri) {
            Ok(opaque_handle) => {
                self.opaque_handle = opaque_handle;
                Ok(())
            }
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to connect to PostgreSQL: {}", err));
                Err(err.into())
            }
        }
    }

    // Queries the PostgreSQL database using the provided SQL query, returns a PostGreResponse.
    pub fn query<T>(&self, query: &str) -> Result<PostGreResponse<T>, Box<dyn std::error::Error>>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        klave::notifier::send_string(query);
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        match klave::sql::query(&self.opaque_handle, query) {
            Ok(result) => {
                let response = match serde_json::from_str::<PostGreResponse<T>>(&result) {
                    Ok(res) => res,
                    Err(e) => {
                        klave::notifier::send_string(&format!("Failed to parse query result: {}", e));
                        return Err(e.into());
                    }
                };
                Ok(response)
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Query failed: {}", err));
                Err(err.into())
            }
        }
    }

    // Executes a SQL command on the PostgreSQL database, returns the result as a String.
    pub fn execute(&self, query: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        klave::notifier::send_string(query);
        match klave::sql::execute(&self.opaque_handle, query) {
            Ok(result) => Ok(result),
            Err(err) => {
                klave::notifier::send_string(&format!("Execution failed: {}", err));
                Err(err.into())
            }
        }
    }

    // Encrypts the specified columns in the given DBTable.
    pub fn encrypt_columns(&mut self, db_table: DBTable) -> Result<(), String> {

        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }

        // Retrieve the table data properties
        let fields = match self.get_table_properties(&db_table.table) {
            Ok(fields) => fields,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to get table properties: {}", err));
                return Err(err.to_string());
            }
        };

        // // Find the Primary key field
        // let primary_key_field = self.get_table_primary_key(&db_table.table)
        //     .map_err(|e| {
        //         klave::notifier::send_string(&format!("Failed to get primary key field: {}", e));
        //         e.to_string()
        //     })?;

        let table_name = &db_table.table;

        // Retrieve the primary key index and the columns to encrypt
        let answer: PostGreResponse<Vec<Vec<Value>>> = match self.get_columns_to_encrypt(&db_table.primary_key, &db_table)
        {
            Ok(columns) => columns,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to get columns to encrypt: {}", err));
                return Err(err.to_string());
            }
        };

        // Convert resultset
        let mut processed_rows: Vec<Vec<Value>> = answer.resultset;

        // Retrieve the master key
        let master_key_name = self.master_key_name.clone().ok_or("Master key name not set")?;
        let master_key = match klave::crypto::subtle::load_key(master_key_name.as_str()) {
            Ok(key) => key,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load master key: {}", err));
                return Err(err.to_string());
            }
        };

        // Parse processed rows and encrypt each column
        for (idx, row) in processed_rows.iter_mut().enumerate() {
            for (idy, value) in row.iter_mut().enumerate() {
                if idy == 0 {
                    // Skip primary key column
                    continue;
                }
                // Convert serde Value in bytes
                let value_in_bytes = match get_serde_value_into_bytes(&value) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        klave::notifier::send_string(&format!("Failed to convert value to bytes: {}", err));
                        return Err(err.to_string());
                    }
                };
                // Derive AES-GCM key for the column
                let aes_gcm_key = match derive_aes_gcm_key(&master_key, db_table.table.clone(), fields[idy].name.clone()) {
                    Ok(key) => key,
                    Err(err) => {
                        klave::notifier::send_string(&format!("Failed to derive AES-GCM key: {}", err));
                        return Err(err.to_string());
                    }
                };
                // Compute the iv deterministically from the point of view of the value to encrypt.
                // I derive a key from the master key and the value to encrypt, export it as raw bytes, and use the first 12 bytes as the iv.
                let iv = match derive_iv(&master_key, fields[idy].name.clone(), value.clone())
                {
                    Ok(res) => res,
                    Err(err) => {
                        klave::notifier::send_string(&format!("Failed to derive AES-GCM key: {}", err));
                        return Err(err.to_string());
                    }
                };
                // Encrypt the value with the derived AES-GCM key
                let aes_gcm_params = AesGcmParams {
                    iv: iv.clone(),
                    additional_data: vec![], // No additional data
                    tag_length: 128, // 128 bits
                };
                let encrypt_algo = crypto::subtle::EncryptAlgorithm::AesGcm(aes_gcm_params);
                let mut encrypted_value = match klave::crypto::subtle::encrypt(&encrypt_algo, &aes_gcm_key, &value_in_bytes) {
                    Ok(encrypted) => encrypted,
                    Err(err) => {
                        klave::notifier::send_string(&format!("Failed to encrypt value: {}", err));
                        return Err(err.to_string());
                    }
                };
                let mut iv_and_encrypted = iv;
                iv_and_encrypted.append(&mut encrypted_value);
                // Encode the IV and encrypted value as a hex string
                let encoded_iv_value = encode(&iv_and_encrypted);

                //update the value with the encrypted value
                *value = serde_json::Value::String(encoded_iv_value);
            }
        }

        match self.update(processed_rows, answer.fields.clone(), table_name.clone())
        {
            Ok(_) => {
                klave::notifier::send_string(&format!("Table {} successfully encrypted", table_name.clone()));
            },
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to update: {}", err));
                return Err(err.to_string());
            }
        };

        Ok(())
    }

    fn get_table_properties(&self, table_name: &str) -> Result<Vec<Field>, Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        let query = format!("SELECT * FROM {} LIMIT 1", table_name);

        match self.query::<Vec<Vec<Value>>>(&query) {
            Ok(response) => {
                let fields: Vec<Field> = response.fields;
                Ok(fields)
            },
            Err(err) => Err(err),
        }
    }

    fn get_table_primary_key(&self, table_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        // Build the query to get the primary key column name
        let query = format!("SELECT kcu.column_name FROM information_schema.table_constraints AS tc JOIN information_schema.key_column_usage AS kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public' AND tc.table_name = '{}' ORDER BY kcu.ordinal_position;", table_name);

        match self.query::<String>(&query) {
            Ok(response) => {
                if response.fields.is_empty() {
                    Err("No primary key found for the table".into())
                } else {
                    Ok(response.resultset.clone())
                }
            },
            Err(err) => Err(err),
        }
    }

    fn get_columns_to_encrypt(&self, primary_key_field: &String, db_table: &DBTable) -> Result<PostGreResponse<Vec<Vec<Value>>>, Box<dyn std::error::Error>> {
        // Check client ID
        let client_id = utils::get_client_id();
        if client_id != self.client_id {
            klave::notifier::send_string("ERROR: Client ID mismatch");
            return Err("Client ID mismatch".into());
        }
        // Build the query to retrieve the primary key and columns to encrypt
        let columns = db_table.columns.join(",");
        let query = format!("SELECT {},{} FROM {}", primary_key_field, columns, db_table.table);
        let result = match self.query::<Vec<Vec<Value>>>(&query) {
            Ok(response) => response,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to get columns to encrypt: {}", err));
                return Err(err);
            }
        };
        Ok(result)
    }

    fn update(&self, processed_rows: Vec<Vec<Value>>, fields: Vec<Field>, table: String) -> Result<(), Box<dyn std::error::Error>> {
        let query = self.build_update_query(processed_rows.clone(), fields, table.clone())?;
        // Execute the update
        let _ = match self.execute(&query)
        {
            Ok(_) => {
                klave::notifier::send_string(&format!("Table {} has been encrypted", table));
            }
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to encrypt: {}", err));
            }
        };
        Ok(())
    }

    fn build_update_query(&self, processed_rows: Vec<Vec<Value>>, fields: Vec<Field>, table: String) -> Result<String, Box<dyn std::error::Error>> {

        // Iterate over the processed rows and build the update query
        if processed_rows.is_empty() {
            return Err("No rows to update".into());
        }
        // Primary key field
        let pk = &fields[0].name;
        // Retrieve the column names from the fields
        let column_names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
        // All columns names
        let all_columns = column_names.join(",");
        // Build the update query
        let mut query = format!("WITH new_values ({}) AS (VALUES ", all_columns);
        // List all new values
        query.push_str(flatten_vec_of_vec_values_to_single_string(processed_rows).as_str());
        // Update
        query .push_str(&format!(") UPDATE {} SET ", table));
        // Update query
        column_names.iter().enumerate().for_each(|(i, column_name)| {
            query.push_str(&format!("{} = new_values.{}", column_name, column_name));
            if i < column_names.len() - 1 {
                query.push_str(", ");
            }
        });
        query.push_str(&format!(" FROM new_values WHERE {}.{} = new_values.{}", table, pk, pk));

        Ok(query)
    }

    pub fn build_encrypted_query(&self, input: ReadEncryptedTableInput) -> Result<String, Box<dyn std::error::Error>> {
        let table = input.table;
        let column = input.encrypted_column;
        let mut values = input.values;
        let mut query = "".to_string();

        // Retrieve the master key
        let master_key_name = self.master_key_name.clone().ok_or("Master key name not set")?;
        let master_key = match klave::crypto::subtle::load_key(master_key_name.as_str()) {
            Ok(key) => key,
            Err(err) => {
                klave::notifier::send_string(&format!("Failed to load master key: {}", err));
                return Err(err);
            }
        };

        for (idx,value) in values.iter_mut().enumerate() {
            // Convert serde Value in bytes
            let value_in_bytes: &[u8] = value.as_bytes();
            // Derive AES-GCM key for the column
            let aes_gcm_key = match derive_aes_gcm_key(&master_key, table.clone(), column.clone()) {
                Ok(key) => key,
                Err(err) => {
                    klave::notifier::send_string(&format!("Failed to derive AES-GCM key: {}", err));
                    return Err(err);
                }
            };
            // Compute the iv deterministically from the point of view of the value to encrypt.
            // I derive a key from the master key and the value to encrypt, export it as raw bytes, and use the first 12 bytes as the iv.
            let iv = match derive_iv(&master_key, column.clone(), serde_json::Value::String(value.clone()))
            {
                Ok(res) => res,
                Err(err) => {
                    klave::notifier::send_string(&format!("Failed to derive AES-GCM key: {}", err));
                    return Err(err);
                }
            };
            // Encrypt the value with the derived AES-GCM key
            let aes_gcm_params = AesGcmParams {
                iv: iv.clone(),
                additional_data: vec![], // No additional data
                tag_length: 128, // 128 bits
            };
            let encrypt_algo = crypto::subtle::EncryptAlgorithm::AesGcm(aes_gcm_params);
            let mut encrypted_value = match klave::crypto::subtle::encrypt(&encrypt_algo, &aes_gcm_key, &value_in_bytes) {
                Ok(encrypted) => encrypted,
                Err(err) => {
                    klave::notifier::send_string(&format!("Failed to encrypt value: {}", err));
                    return Err(err);
                }
            };
            let mut iv_and_encrypted = iv;
            iv_and_encrypted.append(&mut encrypted_value);
            // Encode the IV and encrypted value as a hex string
            let encoded_iv_value = encode(&iv_and_encrypted);
            //replace in values
            *value = encoded_iv_value;
        }

        let list_values = values.join(",");

        query.push_str(&format!("SELECT * FROM {} WHERE {} in ({})", table, column, list_values));

        Ok(query)
    }

}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::Value;

    use super::*;

    //Example of answer from the PostGreSql service
    #[test]
    fn test_deserialization() {
        let json_data = r#"
        {
            "fields": [
                {
                    "name": "product_id",
                    "type": 3,
                    "size": 18446744073709551615,
                    "scale": 0,
                    "nullable": true,
                    "description": null
                },
                {
                    "name": "name",
                    "type": 12,
                    "size": 104,
                    "scale": 0,
                    "nullable": true,
                    "description": null
                },
                {
                    "name": "price",
                    "type": 15,
                    "size": 655366,
                    "scale": 0,
                    "nullable": true,
                    "description": null
                }
            ],
            "resultset": [
                [
                    1,
                    "Laptop",
                    "1200.00"
                ],
                [
                    2,
                    "Mouse",
                    "25.50"
                ]
            ]
        }
        "#;

        let response: Vec<HashMap<String, Value>> = match serde_json::from_str::<PostGreResponse<Vec<Vec<Value>>>>(json_data) {
            Ok(res) => {
                let mut processed_rows: Vec<HashMap<String, Value>> = Vec::new();
                for row in res.resultset {
                    let mut processed_row = HashMap::new();
                    for (i, value) in row.into_iter().enumerate() {
                        let field_name = res.fields.get(i).map(|f| f.name.clone()).unwrap_or_default();
                        processed_row.insert(field_name, value);
                    }
                    processed_rows.push(processed_row);
                }
                processed_rows
            },
            Err(e) => {
                panic!("Failed to deserialize JSON: {}", e);
            }
        };

        // You can now access the data
        println!("{:?}", response);

        // Example of accessing fields
        // assert_eq!(response.fields.len(), 3);
        // assert_eq!(response.fields[0].name, "product_id");
        // assert_eq!(response.fields[0].field_type, 3);
        // assert_eq!(response.fields[0].description, None);

        // // Example of accessing resultset
        // assert_eq!(response.resultset.len(), 2);
        // assert_eq!(response.resultset[0][0], Value::from(1));
        // assert_eq!(response.resultset[0][1], Value::String("Laptop".to_string()));
        // assert_eq!(response.resultset[0][2], Value::String("1200.00".to_string()));

        if let Some(first_row_map) = response.first() {
            if let Some(product_id_value) = first_row_map.get("product_id") {
                if let Some(id) = product_id_value.as_i64() {
                    println!("\nExample access: Product ID of first row is {}", id);
                } else {
                    println!("\nExample access: Product ID of first row is not an integer: {:?}", product_id_value);
                }
            }
        }
    }
}