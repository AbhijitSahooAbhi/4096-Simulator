<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

require_once '../db/init.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['task']) || empty(trim($data['task']))) {
        echo json_encode(['error' => 'Task cannot be empty']);
        exit;
    }

    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $sql = "INSERT INTO todos (task) VALUES (:task)";
        $stmt = $db->prepare($sql);
        $stmt->bindParam(':task', $data['task']);
        
        if ($stmt->execute()) {
            $id = $db->lastInsertId();
            echo json_encode([
                'success' => true,
                'id' => $id,
                'task' => $data['task'],
                'completed' => 0
            ]);
        } else {
            echo json_encode(['error' => 'Failed to create task']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
} else {
    echo json_encode(['error' => 'Invalid request method']);
}
?>
