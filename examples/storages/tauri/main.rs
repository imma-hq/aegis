use tauri::State;
use std::sync::Mutex;
use sqlcipher::Connection;
use keyring::Entry;

const DB_PATH: &str = "aegis_e2ee.db";
const KEYRING_SERVICE: &str = "com.yourapp.aegis";
const KEYRING_ACCOUNT: &str = "sqlcipher_key";

struct DbConnection(Mutex<Option<Connection>>);

#[tauri::command]
async fn save_identity(db: State<'_, DbConnection>, identity: String) -> Result<(), String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    conn.execute(
        "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?1, ?2)",
        ["identity", &identity],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_identity(db: State<'_, DbConnection>) -> Result<Option<String>, String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    let mut stmt = conn.prepare("SELECT value FROM aegis_storage WHERE key = ?1")
        .map_err(|e| e.to_string())?;
    let res: Option<String> = stmt.query_row(["identity"], |row| row.get(0)).optional()
        .map_err(|e| e.to_string())?;
    Ok(res)
}

#[tauri::command]
async fn delete_identity(db: State<'_, DbConnection>) -> Result<(), String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    conn.execute("DELETE FROM aegis_storage WHERE key = ?1", ["identity"])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn save_session(db: State<'_, DbConnection>, session_id: String, session: String) -> Result<(), String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    conn.execute(
        "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?1, ?2)",
        [format!("session_{}", session_id).as_str(), &session],
    ).map_err(|e| e.to_string())?;

    // Update session list
    let mut list: Vec<String> = match get_session_list_impl(conn)? {
        Some(s) => serde_json::from_str(&s).map_err(|e| e.to_string())?,
        None => vec![],
    };
    if !list.contains(&session_id) {
        list.push(session_id);
        let list_json = serde_json::to_string(&list).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES ('_sessions_list', ?1)",
            [&list_json],
        ).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn get_session(db: State<'_, DbConnection>, session_id: String) -> Result<Option<String>, String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    let mut stmt = conn.prepare("SELECT value FROM aegis_storage WHERE key = ?1")
        .map_err(|e| e.to_string())?;
    let key = format!("session_{}", session_id);
    let res: Option<String> = stmt.query_row([&key], |row| row.get(0)).optional()
        .map_err(|e| e.to_string())?;
    Ok(res)
}

#[tauri::command]
async fn delete_session(db: State<'_, DbConnection>, session_id: String) -> Result<(), String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    let key = format!("session_{}", session_id);
    conn.execute("DELETE FROM aegis_storage WHERE key = ?1", [&key])
        .map_err(|e| e.to_string())?;

    let mut list: Vec<String> = match get_session_list_impl(conn)? {
        Some(s) => serde_json::from_str(&s).map_err(|e| e.to_string())?,
        None => vec![],
    };
    list.retain(|id| id != &session_id);
    let list_json = serde_json::to_string(&list).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES ('_sessions_list', ?1)",
        [&list_json],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn list_sessions(db: State<'_, DbConnection>) -> Result<Vec<String>, String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    match get_session_list_impl(conn)? {
        Some(s) => serde_json::from_str(&s).map_err(|e| e.to_string()),
        None => Ok(vec![]),
    }
}

#[tauri::command]
async fn delete_all_sessions(db: State<'_, DbConnection>) -> Result<(), String> {
    let conn = db.0.lock().unwrap();
    let conn = conn.as_ref().ok_or("DB not initialized")?;
    let list: Vec<String> = match get_session_list_impl(conn)? {
        Some(s) => serde_json::from_str(&s).map_err(|e| e.to_string())?,
        None => vec![],
    };
    for id in list {
        let key = format!("session_{}", id);
        conn.execute("DELETE FROM aegis_storage WHERE key = ?1", [&key])
            .map_err(|e| e.to_string())?;
    }
    conn.execute("DELETE FROM aegis_storage WHERE key = '_sessions_list'", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn get_session_list_impl(conn: &Connection) -> Result<Option<String>, String> {
    let mut stmt = conn.prepare("SELECT value FROM aegis_storage WHERE key = '_sessions_list'")
        .map_err(|e| e.to_string())?;
    stmt.query_row([], |row| row.get(0)).optional().map_err(|e| e.to_string())
}

fn init_db() -> Result<Connection, Box<dyn std::error::Error>> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
    let key = match entry.get_password() {
        Ok(k) => k,
        Err(_) => {
            let new_key: String = (0..64).map(|_| format!("{:x}", rand::random::<u8>())).collect();
            entry.set_password(&new_key)?;
            new_key
        }
    };

    let conn = Connection::open_with_key(DB_PATH, &key)?;
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS aegis_storage (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
    ")?;
    Ok(conn)
}

fn main() {
    let db = init_db().expect("Failed to initialize secure DB");
    tauri::Builder::default()
        .manage(DbConnection(Mutex::new(Some(db))))
        .invoke_handler(tauri::generate_handler![
            save_identity, get_identity, delete_identity,
            save_session, get_session, delete_session,
            list_sessions, delete_all_sessions
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
