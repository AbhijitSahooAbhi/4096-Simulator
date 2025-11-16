<?php
header('Content-Type: application/json');

$todos = json_decode(file_get_contents('todos.json'), true) ?? [];
echo json_encode($todos);
?>