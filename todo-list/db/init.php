<?php
// Database initialization and connection

class Database {
    private $db;
    private $dbPath;

    public function __construct() {
        $this->dbPath = __DIR__ . '/todos.db';
        $this->connect();
        $this->createTable();
    }

    private function connect() {
        try {
            $this->db = new PDO('sqlite:' . $this->dbPath);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die(json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]));
        }
    }

    private function createTable() {
        $sql = "CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            completed INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )";
        
        try {
            $this->db->exec($sql);
        } catch (PDOException $e) {
            die(json_encode(['error' => 'Table creation failed: ' . $e->getMessage()]));
        }
    }

    public function getConnection() {
        return $this->db;
    }
}
?>
