<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $todo = $data['todo'] ?? '';

    if (!empty($todo)) {
        $todos = json_decode(file_get_contents('todos.json'), true) ?? [];
        $todos[] = ['text' => $todo, 'completed' => false];
        file_put_contents('todos.json', json_encode($todos));
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Todo cannot be empty']);
    }
} else {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
}
?>