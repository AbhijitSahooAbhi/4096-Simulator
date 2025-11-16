<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>To-Do List App</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>📝 My To-Do List</h1>
            <p class="subtitle">Stay organized and productive</p>
        </header>

        <div class="todo-input-section">
            <input 
                type="text" 
                id="todoInput" 
                placeholder="What needs to be done?" 
                autocomplete="off"
            >
            <button id="addBtn" class="btn btn-primary">
                <span>Add Task</span>
            </button>
        </div>

        <div class="filter-section">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="active">Active</button>
            <button class="filter-btn" data-filter="completed">Completed</button>
        </div>

        <div class="stats">
            <span id="taskCount">0 tasks</span>
        </div>

        <ul id="todoList" class="todo-list">
            <!-- Tasks will be dynamically added here -->
        </ul>

        <div class="empty-state" id="emptyState">
            <div class="empty-icon">📋</div>
            <p>No tasks yet. Add one to get started!</p>
        </div>
    </div>

    <script src="js/app.js"></script>
</body>
</html>
