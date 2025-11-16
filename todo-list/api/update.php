<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: PUT, PATCH');

require_once '../db/init.php';

if ($_SERVER['REQUEST_METHOD'] === 'PUT' || $_SERVER['REQUEST_METHOD'] === 'PATCH') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['id'])) {
        echo json_encode(['error' => 'Task ID is required']);
        exit;
    }

    try {
        $database = new Database();
        $db = $database->getConnection();
        
        // Check if we're updating task text or completion status
        if (isset($data['task'])) {
            $sql = "UPDATE todos SET task = :task, updated_at = CURRENT_TIMESTAMP WHERE id = :id";
            $stmt = $db->prepare($sql);
            $stmt->bindParam(':task', $data['task']);
            $stmt->bindParam(':id', $data['id']);
        } elseif (isset($data['completed'])) {
            $sql = "UPDATE todos SET completed = :completed, updated_at = CURRENT_TIMESTAMP WHERE id = :id";
            $stmt = $db->prepare($sql);
            $stmt->bindParam(':completed', $data['completed'], PDO::PARAM_INT);
            $stmt->bindParam(':id', $data['id']);
        } else {
            echo json_encode(['error' => 'No update data provided']);
            exit;
        }
        
        if ($stmt->execute()) {
            echo json_encode([
                'success' => true,
                'message' => 'Task updated successfully'
            ]);
        } else {
            echo json_encode(['error' => 'Failed to update task']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
} else {
    echo json_encode(['error' => 'Invalid request method']);
}
?>
