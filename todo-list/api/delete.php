<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: DELETE');

require_once '../db/init.php';

if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['id'])) {
        echo json_encode(['error' => 'Task ID is required']);
        exit;
    }

    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $sql = "DELETE FROM todos WHERE id = :id";
        $stmt = $db->prepare($sql);
        $stmt->bindParam(':id', $data['id']);
        
        if ($stmt->execute()) {
            echo json_encode([
                'success' => true,
                'message' => 'Task deleted successfully'
            ]);
        } else {
            echo json_encode(['error' => 'Failed to delete task']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
} else {
    echo json_encode(['error' => 'Invalid request method']);
}
?>
