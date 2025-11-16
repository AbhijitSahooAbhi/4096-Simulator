<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $index = $data['index'] ?? -1;
    $completed = $data['completed'] ?? false;

    if ($index >= 0) {
        $todos = json_decode(file_get_contents('todos.json'), true) ?? [];
        if (isset($todos[$index])) {
            $todos[$index]['completed'] = $completed;
            file_put_contents('todos.json', json_encode($todos));
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Todo not found']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Invalid index']);
    }
} else {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
}
?>