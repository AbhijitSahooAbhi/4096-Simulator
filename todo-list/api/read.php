<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once '../db/init.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    $filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';
    
    $sql = "SELECT * FROM todos";
    
    if ($filter === 'active') {
        $sql .= " WHERE completed = 0";
    } elseif ($filter === 'completed') {
        $sql .= " WHERE completed = 1";
    }
    
    $sql .= " ORDER BY created_at DESC";
    
    $stmt = $db->query($sql);
    $todos = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'todos' => $todos
    ]);
} catch (PDOException $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>
